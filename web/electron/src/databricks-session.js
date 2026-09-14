// Bridge a Databricks OAuth access token into a DBAUTH web-session cookie.
//
// Calls the login service's /auth/session/create (the OAuth→session bridge from
// the Databricks One mobile design) with a bearer token; that endpoint mints an
// SMv2 session and returns it as a 302 -> next_url with Set-Cookie: DBAUTH. We
// let net.request FOLLOW that redirect so Electron commits the cookie into the
// target window's session jar, then confirm it landed, so the /omnigent SPA
// opens already authenticated. databricks-oauth.js supplies/refreshes the token;
// main.js calls ensureDatabricksSession at the pre-load and session-expiry seams.

"use strict";

const { net } = require("electron");
const {
  databricksOAuthConfigured,
  runInteractiveLogin,
  getValidStoredToken,
  saveWorkspaceToken,
  loadTokens,
  isTrustedDatabricksOrigin,
} = require("./databricks-oauth");
const { parseAccountFromToken, listRunningWorkspaces } = require("./databricks-account");

const SESSION_CREATE_PATH = "/auth/session/create";
// Bound on the session-create request so a stalled socket can't hang connect.
const NETWORK_TIMEOUT_MS = 20_000;

/**
 * Ensure ``ses`` holds a live DBAUTH cookie for a workspace, and return that
 * workspace origin. Two entry points:
 *
 * - Connect (``interactive: true``): reuse a stored token for ``origin`` if
 *   there is one (a relaunch to a workspace origin, or an unexpired session);
 *   otherwise run the browser login. An account-scoped (SPOG) login lists the
 *   account's workspaces, calls ``pickWorkspace``, and bridges the account token
 *   to the chosen one — persisting it keyed by that workspace origin so the
 *   expiry path can find it.
 * - Session expiry (``interactive: false``): ``origin`` is the (already
 *   resolved) workspace origin, so the stored token is found and refreshed and
 *   the cookie re-minted against the SAME workspace — no browser, no picker.
 *
 * @param {Electron.Session} ses The session whose cookie jar to seed.
 * @param {string} origin The entered/pinned origin (account or workspace host).
 * @param {{ interactive?: boolean, nextPath?: string,
 *   pickWorkspace?: (workspaces: Array<{workspaceId: string, name: string, fqdn: string}>)
 *     => Promise<{fqdn: string, name: string} | null> }} [opts]
 * @returns {Promise<string>} The workspace origin the session was created for.
 */
async function ensureDatabricksSession(
  ses,
  origin,
  { interactive = true, nextPath = "/omnigent", pickWorkspace } = {},
) {
  let bridgeOrigin;
  let accessToken;

  // 1. Reuse a stored token bound to this origin — covers the expiry path (origin
  //    is the resolved workspace) and a relaunch straight to a workspace origin.
  //    The stored token already targets this origin, so no picker is needed.
  if (loadTokens(origin)) {
    try {
      accessToken = await getValidStoredToken(origin);
      bridgeOrigin = origin;
    } catch (e) {
      if (!interactive) throw e;
      console.warn(`[omnigent] databricks: stored token unusable, re-authenticating: ${e.message}`);
    }
  }

  // 2. Nothing usable stored → interactive browser login (connect only).
  if (!accessToken) {
    if (!interactive) {
      throw new Error("no valid Databricks token and interactive login is disabled");
    }
    const { tokens, issuerOrigin } = await runInteractiveLogin(origin);
    const account = parseAccountFromToken(tokens.access_token);
    if (account) {
      // Account-scoped (SPOG): the account host has no /auth/session/create, so
      // resolve the account's workspaces, let the user pick, and bridge to that
      // workspace. Persist keyed by the workspace origin (with the account
      // context) so silent refresh later hits the account token endpoint.
      if (!isTrustedDatabricksOrigin(account.accountOrigin)) {
        throw new Error(`refusing to use an untrusted account origin: ${account.accountOrigin}`);
      }
      const workspaces = await listRunningWorkspaces(account, tokens.access_token);
      if (workspaces.length === 0) {
        throw new Error("no running workspaces available for this account");
      }
      if (typeof pickWorkspace !== "function") {
        throw new Error("account-scoped login requires a workspace picker");
      }
      const picked = await pickWorkspace(workspaces);
      if (!picked) throw new Error("workspace selection cancelled");
      bridgeOrigin = `https://${picked.fqdn}`;
      saveWorkspaceToken(bridgeOrigin, tokens, {
        origin: account.accountOrigin,
        id: account.accountId,
      });
      console.log(`[omnigent] databricks session: bridging to workspace ${bridgeOrigin}`);
    } else {
      // Workspace-scoped: the token targets the issuer (the entered workspace).
      bridgeOrigin = issuerOrigin;
      saveWorkspaceToken(bridgeOrigin, tokens, null);
    }
    accessToken = tokens.access_token;
  }

  // Never send the bearer to a non-Databricks host.
  if (!isTrustedDatabricksOrigin(bridgeOrigin)) {
    throw new Error(`refusing to send credentials to untrusted workspace origin: ${bridgeOrigin}`);
  }

  await mintSessionCookie(ses, bridgeOrigin, accessToken, nextPath);
  return bridgeOrigin;
}

/**
 * Exchange the bearer token for a DBAUTH cookie via /auth/session/create. The
 * endpoint replies 302 -> next_url with Set-Cookie: DBAUTH; we let net.request
 * follow the redirect so Electron commits that cookie into ``ses`` (Electron
 * hides Set-Cookie from the JS-visible redirect headers, so we read the jar
 * rather than parse the header), then confirm DBAUTH is present.
 */
async function mintSessionCookie(ses, origin, accessToken, nextPath) {
  const status = await new Promise((resolve, reject) => {
    const url = `${origin}${SESSION_CREATE_PATH}?next_url=${encodeURIComponent(nextPath)}`;
    // useSessionCookies:true is required for the response's Set-Cookie to be
    // stored in `ses` (it defaults to false — session:ses alone won't persist
    // cookies). Default redirect mode = follow, so Electron processes the 302
    // (committing DBAUTH into the jar) before landing on next_url.
    const request = net.request({ method: "GET", url, session: ses, useSessionCookies: true });
    request.setHeader("Authorization", `Bearer ${accessToken}`);
    const timer = setTimeout(() => request.abort(), NETWORK_TIMEOUT_MS);
    request.on("response", (response) => {
      response.on("data", () => {});
      response.on("end", () => {
        clearTimeout(timer);
        resolve(response.statusCode);
      });
    });
    request.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    request.end();
  });

  // A successful bridge follows the 302 to next_url and ends < 400. An error
  // (e.g. 401/403 when the endpoint isn't enabled for this account) ends >= 400
  // and must NOT be reported as success just because a stale DBAUTH lingers.
  if (status >= 400) {
    throw new Error(`${SESSION_CREATE_PATH} returned HTTP ${status}`);
  }
  const jar = await ses.cookies.get({ url: origin, name: "DBAUTH" });
  if (jar.length === 0) {
    throw new Error(
      `${SESSION_CREATE_PATH}: no DBAUTH cookie stored in the session (final HTTP ${status})`,
    );
  }
  console.log(`[omnigent] databricks session: signed in to ${origin}`);
}

module.exports = {
  databricksOAuthConfigured,
  ensureDatabricksSession,
};
