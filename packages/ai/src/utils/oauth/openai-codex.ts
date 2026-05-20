/**
 * OpenAI Codex (ChatGPT OAuth) flow
 *
 * NOTE: This module uses Node.js crypto and http for the OAuth callback.
 * It is only intended for CLI use, not browser environments.
 */

// NEVER convert to top-level imports - breaks browser/Vite builds
let _randomBytes: typeof import("node:crypto").randomBytes | null = null;
let _http: typeof import("node:http") | null = null;
if (typeof process !== "undefined" && (process.versions?.node || process.versions?.bun)) {
	import("node:crypto").then((m) => {
		_randomBytes = m.randomBytes;
	});
	import("node:http").then((m) => {
		_http = m;
	});
}

import { pollOAuthDeviceCodeFlow } from "./device-code.ts";
import { oauthErrorHtml, oauthSuccessHtml } from "./oauth-page.ts";
import { generatePKCE } from "./pkce.ts";
import type {
	OAuthCredentials,
	OAuthDeviceCodeInfo,
	OAuthLoginCallbacks,
	OAuthPrompt,
	OAuthProviderInterface,
} from "./types.ts";

const CALLBACK_HOST = process.env.PI_OAUTH_CALLBACK_HOST || "127.0.0.1";
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTH_BASE_URL = "https://auth.openai.com";
const AUTHORIZE_URL = `${AUTH_BASE_URL}/oauth/authorize`;
const TOKEN_URL = `${AUTH_BASE_URL}/oauth/token`;
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const DEVICE_USER_CODE_URL = `${AUTH_BASE_URL}/api/accounts/deviceauth/usercode`;
const DEVICE_TOKEN_URL = `${AUTH_BASE_URL}/api/accounts/deviceauth/token`;
const DEVICE_VERIFICATION_URI = `${AUTH_BASE_URL}/codex/device`;
const DEVICE_REDIRECT_URI = `${AUTH_BASE_URL}/deviceauth/callback`;
const DEVICE_CODE_TIMEOUT_SECONDS = 15 * 60;
export const OPENAI_CODEX_BROWSER_LOGIN_METHOD = "browser";
export const OPENAI_CODEX_DEVICE_CODE_LOGIN_METHOD = "device_code";
const SCOPE = "openid profile email offline_access";
const JWT_CLAIM_PATH = "https://api.openai.com/auth";

type TokenSuccess = { type: "success"; access: string; refresh: string; expires: number };
type TokenFailure = { type: "failed"; message: string; status?: number };
type TokenResult = TokenSuccess | TokenFailure;

type DeviceAuthInfo = {
	deviceAuthId: string;
	userCode: string;
	intervalSeconds: number;
};

type DeviceTokenSuccess = {
	authorizationCode: string;
	codeChallenge: string;
	codeVerifier: string;
};

type JwtPayload = {
	[JWT_CLAIM_PATH]?: {
		chatgpt_account_id?: string;
	};
	[key: string]: unknown;
};

function createState(): string {
	if (!_randomBytes) {
		throw new Error("OpenAI Codex OAuth is only available in Node.js environments");
	}
	return _randomBytes(16).toString("hex");
}

function parseAuthorizationInput(input: string): { code?: string; state?: string } {
	const value = input.trim();
	if (!value) return {};

	try {
		const url = new URL(value);
		return {
			code: url.searchParams.get("code") ?? undefined,
			state: url.searchParams.get("state") ?? undefined,
		};
	} catch {
		// not a URL
	}

	if (value.includes("#")) {
		const [code, state] = value.split("#", 2);
		return { code, state };
	}

	if (value.includes("code=")) {
		const params = new URLSearchParams(value);
		return {
			code: params.get("code") ?? undefined,
			state: params.get("state") ?? undefined,
		};
	}

	return { code: value };
}

function decodeJwt(token: string): JwtPayload | null {
	try {
		const parts = token.split(".");
		if (parts.length !== 3) return null;
		const payload = parts[1] ?? "";
		const decoded = atob(payload);
		return JSON.parse(decoded) as JwtPayload;
	} catch {
		return null;
	}
}

async function exchangeAuthorizationCode(
	code: string,
	verifier: string,
	redirectUri: string = REDIRECT_URI,
	signal?: AbortSignal,
): Promise<TokenResult> {
	let response: Response;
	try {
		response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				client_id: CLIENT_ID,
				code,
				code_verifier: verifier,
				redirect_uri: redirectUri,
			}),
			signal,
		});
	} catch (error) {
		if (signal?.aborted) {
			throw new Error("Login cancelled");
		}
		throw error;
	}

	if (!response.ok) {
		const text = await response.text().catch(() => "");
		return {
			type: "failed",
			status: response.status,
			message: `OpenAI Codex token exchange failed (${response.status}): ${text || response.statusText}`,
		};
	}

	const json = (await response.json()) as {
		access_token?: string;
		refresh_token?: string;
		expires_in?: number;
	};

	if (!json.access_token || !json.refresh_token || typeof json.expires_in !== "number") {
		return {
			type: "failed",
			message: `OpenAI Codex token exchange response missing fields: ${JSON.stringify(json)}`,
		};
	}

	return {
		type: "success",
		access: json.access_token,
		refresh: json.refresh_token,
		expires: Date.now() + json.expires_in * 1000,
	};
}

async function refreshAccessToken(refreshToken: string): Promise<TokenResult> {
	try {
		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_id: CLIENT_ID,
			}),
		});

		if (!response.ok) {
			const text = await response.text().catch(() => "");
			return {
				type: "failed",
				status: response.status,
				message: `OpenAI Codex token refresh failed (${response.status}): ${text || response.statusText}`,
			};
		}

		const json = (await response.json()) as {
			access_token?: string;
			refresh_token?: string;
			expires_in?: number;
		};

		if (!json.access_token || !json.refresh_token || typeof json.expires_in !== "number") {
			return {
				type: "failed",
				message: `OpenAI Codex token refresh response missing fields: ${JSON.stringify(json)}`,
			};
		}

		return {
			type: "success",
			access: json.access_token,
			refresh: json.refresh_token,
			expires: Date.now() + json.expires_in * 1000,
		};
	} catch (error) {
		return {
			type: "failed",
			message: `OpenAI Codex token refresh error: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
}

function parseDeviceIntervalSeconds(value: unknown): number | null {
	const intervalSeconds = typeof value === "string" ? Number(value.trim()) : value;
	if (typeof intervalSeconds !== "number" || !Number.isFinite(intervalSeconds) || intervalSeconds <= 0) {
		return null;
	}
	return intervalSeconds;
}

function parseObjectJson(text: string, context: string): Record<string, unknown> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new Error(`${context}: ${text}`);
	}

	if (!parsed || typeof parsed !== "object") {
		throw new Error(`${context}: ${text}`);
	}

	return parsed as Record<string, unknown>;
}

function parseDeviceAuthInfo(text: string): DeviceAuthInfo {
	const json = parseObjectJson(text, "Invalid OpenAI Codex device code response");
	const deviceAuthId = json.device_auth_id;
	const userCode = json.user_code;
	const intervalSeconds = parseDeviceIntervalSeconds(json.interval);

	if (typeof deviceAuthId !== "string" || typeof userCode !== "string" || intervalSeconds === null) {
		throw new Error(`Invalid OpenAI Codex device code response: ${text}`);
	}

	return {
		deviceAuthId,
		userCode,
		intervalSeconds,
	};
}

function parseDeviceTokenSuccess(text: string): DeviceTokenSuccess {
	const json = parseObjectJson(text, "Invalid OpenAI Codex device auth token response");
	const authorizationCode = json.authorization_code;
	const codeChallenge = json.code_challenge;
	const codeVerifier = json.code_verifier;
	if (typeof authorizationCode !== "string" || typeof codeChallenge !== "string" || typeof codeVerifier !== "string") {
		throw new Error(`Invalid OpenAI Codex device auth token response: ${text}`);
	}
	return { authorizationCode, codeChallenge, codeVerifier };
}

async function readResponseDetails(response: Response): Promise<string> {
	const responseBody = await response.text().catch(() => "");
	return responseBody ? `: ${responseBody}` : "";
}

async function startOpenAICodexDeviceAuth(signal?: AbortSignal): Promise<DeviceAuthInfo> {
	let response: Response;
	try {
		response = await fetch(DEVICE_USER_CODE_URL, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ client_id: CLIENT_ID }),
			signal,
		});
	} catch (error) {
		if (signal?.aborted) {
			throw new Error("Login cancelled");
		}
		throw error;
	}

	if (!response.ok) {
		if (response.status === 404) {
			throw new Error(
				"OpenAI Codex device code login is not enabled for this server. Use browser login or verify the server URL.",
			);
		}
		throw new Error(
			`OpenAI Codex device code request failed with status ${response.status}${await readResponseDetails(response)}`,
		);
	}

	return parseDeviceAuthInfo(await response.text());
}

async function pollOpenAICodexDeviceAuth(device: DeviceAuthInfo, signal?: AbortSignal): Promise<DeviceTokenSuccess> {
	return pollOAuthDeviceCodeFlow<DeviceTokenSuccess>({
		intervalSeconds: device.intervalSeconds,
		expiresInSeconds: DEVICE_CODE_TIMEOUT_SECONDS,
		signal,
		poll: async () => {
			let response: Response;
			try {
				response = await fetch(DEVICE_TOKEN_URL, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						device_auth_id: device.deviceAuthId,
						user_code: device.userCode,
					}),
					signal,
				});
			} catch (error) {
				if (signal?.aborted) {
					throw new Error("Login cancelled");
				}
				throw error;
			}

			if (response.ok) {
				return { status: "complete", value: parseDeviceTokenSuccess(await response.text()) };
			}

			if (response.status === 403 || response.status === 404) {
				return { status: "pending" };
			}

			return {
				status: "failed",
				message: `OpenAI Codex device auth failed with status ${response.status}${await readResponseDetails(response)}`,
			};
		},
	});
}

async function createAuthorizationFlow(
	originator: string = "pi",
): Promise<{ verifier: string; state: string; url: string }> {
	const { verifier, challenge } = await generatePKCE();
	const state = createState();

	const url = new URL(AUTHORIZE_URL);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", CLIENT_ID);
	url.searchParams.set("redirect_uri", REDIRECT_URI);
	url.searchParams.set("scope", SCOPE);
	url.searchParams.set("code_challenge", challenge);
	url.searchParams.set("code_challenge_method", "S256");
	url.searchParams.set("state", state);
	url.searchParams.set("id_token_add_organizations", "true");
	url.searchParams.set("codex_cli_simplified_flow", "true");
	url.searchParams.set("originator", originator);

	return { verifier, state, url: url.toString() };
}

type OAuthServerInfo = {
	close: () => void;
	cancelWait: () => void;
	waitForCode: () => Promise<{ code: string } | null>;
};

function startLocalOAuthServer(state: string): Promise<OAuthServerInfo> {
	if (!_http) {
		throw new Error("OpenAI Codex OAuth is only available in Node.js environments");
	}

	let settleWait: ((value: { code: string } | null) => void) | undefined;
	const waitForCodePromise = new Promise<{ code: string } | null>((resolve) => {
		let settled = false;
		settleWait = (value) => {
			if (settled) return;
			settled = true;
			resolve(value);
		};
	});

	const server = _http.createServer((req, res) => {
		try {
			const url = new URL(req.url || "", "http://localhost");
			if (url.pathname !== "/auth/callback") {
				res.statusCode = 404;
				res.setHeader("Content-Type", "text/html; charset=utf-8");
				res.end(oauthErrorHtml("Callback route not found."));
				return;
			}
			if (url.searchParams.get("state") !== state) {
				res.statusCode = 400;
				res.setHeader("Content-Type", "text/html; charset=utf-8");
				res.end(oauthErrorHtml("State mismatch."));
				return;
			}
			const code = url.searchParams.get("code");
			if (!code) {
				res.statusCode = 400;
				res.setHeader("Content-Type", "text/html; charset=utf-8");
				res.end(oauthErrorHtml("Missing authorization code."));
				return;
			}
			res.statusCode = 200;
			res.setHeader("Content-Type", "text/html; charset=utf-8");
			res.end(oauthSuccessHtml("OpenAI authentication completed. You can close this window."));
			settleWait?.({ code });
		} catch {
			res.statusCode = 500;
			res.setHeader("Content-Type", "text/html; charset=utf-8");
			res.end(oauthErrorHtml("Internal error while processing OAuth callback."));
		}
	});

	return new Promise((resolve) => {
		server
			.listen(1455, CALLBACK_HOST, () => {
				resolve({
					close: () => server.close(),
					cancelWait: () => {
						settleWait?.(null);
					},
					waitForCode: () => waitForCodePromise,
				});
			})
			.on("error", (_err: NodeJS.ErrnoException) => {
				settleWait?.(null);
				resolve({
					close: () => {
						try {
							server.close();
						} catch {
							// ignore
						}
					},
					cancelWait: () => {},
					waitForCode: async () => null,
				});
			});
	});
}

function getAccountId(accessToken: string): string | null {
	const payload = decodeJwt(accessToken);
	const auth = payload?.[JWT_CLAIM_PATH];
	const accountId = auth?.chatgpt_account_id;
	return typeof accountId === "string" && accountId.length > 0 ? accountId : null;
}

/**
 * Login with OpenAI Codex OAuth using the Codex device-code flow.
 */
export async function loginOpenAICodexDeviceCode(options: {
	onDeviceCode: (info: OAuthDeviceCodeInfo) => void;
	onProgress?: (message: string) => void;
	signal?: AbortSignal;
}): Promise<OAuthCredentials> {
	const device = await startOpenAICodexDeviceAuth(options.signal);
	options.onDeviceCode({
		userCode: device.userCode,
		verificationUri: DEVICE_VERIFICATION_URI,
		intervalSeconds: device.intervalSeconds,
		expiresInSeconds: DEVICE_CODE_TIMEOUT_SECONDS,
		openBrowser: false,
	});
	const code = await pollOpenAICodexDeviceAuth(device, options.signal);
	const tokenResult = await exchangeAuthorizationCode(
		code.authorizationCode,
		code.codeVerifier,
		DEVICE_REDIRECT_URI,
		options.signal,
	);
	if (tokenResult.type !== "success") {
		throw new Error(tokenResult.message);
	}

	const accountId = getAccountId(tokenResult.access);
	if (!accountId) {
		throw new Error("Failed to extract accountId from token");
	}

	return {
		access: tokenResult.access,
		refresh: tokenResult.refresh,
		expires: tokenResult.expires,
		accountId,
	};
}

/**
 * Login with OpenAI Codex OAuth
 *
 * @param options.onAuth - Called with URL and instructions when auth starts
 * @param options.onPrompt - Called to prompt user for manual code paste (fallback if no onManualCodeInput)
 * @param options.onProgress - Optional progress messages
 * @param options.onManualCodeInput - Optional promise that resolves with user-pasted code.
 *                                    Races with browser callback - whichever completes first wins.
 *                                    Useful for showing paste input immediately alongside browser flow.
 * @param options.originator - OAuth originator parameter (defaults to "pi")
 */
export async function loginOpenAICodex(options: {
	onAuth: (info: { url: string; instructions?: string }) => void;
	onPrompt: (prompt: OAuthPrompt) => Promise<string>;
	onProgress?: (message: string) => void;
	onManualCodeInput?: () => Promise<string>;
	originator?: string;
}): Promise<OAuthCredentials> {
	const { verifier, state, url } = await createAuthorizationFlow(options.originator);
	const server = await startLocalOAuthServer(state);

	options.onAuth({ url, instructions: "A browser window should open. Complete login to finish." });

	let code: string | undefined;
	try {
		if (options.onManualCodeInput) {
			// Race between browser callback and manual input
			let manualCode: string | undefined;
			let manualError: Error | undefined;
			const manualPromise = options
				.onManualCodeInput()
				.then((input) => {
					manualCode = input;
					server.cancelWait();
				})
				.catch((err) => {
					manualError = err instanceof Error ? err : new Error(String(err));
					server.cancelWait();
				});

			const result = await server.waitForCode();

			// If manual input was cancelled, throw that error
			if (manualError) {
				throw manualError;
			}

			if (result?.code) {
				// Browser callback won
				code = result.code;
			} else if (manualCode) {
				// Manual input won (or callback timed out and user had entered code)
				const parsed = parseAuthorizationInput(manualCode);
				if (parsed.state && parsed.state !== state) {
					throw new Error("State mismatch");
				}
				code = parsed.code;
			}

			// If still no code, wait for manual promise to complete and try that
			if (!code) {
				await manualPromise;
				if (manualError) {
					throw manualError;
				}
				if (manualCode) {
					const parsed = parseAuthorizationInput(manualCode);
					if (parsed.state && parsed.state !== state) {
						throw new Error("State mismatch");
					}
					code = parsed.code;
				}
			}
		} else {
			// Original flow: wait for callback, then prompt if needed
			const result = await server.waitForCode();
			if (result?.code) {
				code = result.code;
			}
		}

		// Fallback to onPrompt if still no code
		if (!code) {
			const input = await options.onPrompt({
				message: "Paste the authorization code (or full redirect URL):",
			});
			const parsed = parseAuthorizationInput(input);
			if (parsed.state && parsed.state !== state) {
				throw new Error("State mismatch");
			}
			code = parsed.code;
		}

		if (!code) {
			throw new Error("Missing authorization code");
		}

		const tokenResult = await exchangeAuthorizationCode(code, verifier);
		if (tokenResult.type !== "success") {
			throw new Error(tokenResult.message);
		}

		const accountId = getAccountId(tokenResult.access);
		if (!accountId) {
			throw new Error("Failed to extract accountId from token");
		}

		return {
			access: tokenResult.access,
			refresh: tokenResult.refresh,
			expires: tokenResult.expires,
			accountId,
		};
	} finally {
		server.close();
	}
}

/**
 * Refresh OpenAI Codex OAuth token
 */
export async function refreshOpenAICodexToken(refreshToken: string): Promise<OAuthCredentials> {
	const result = await refreshAccessToken(refreshToken);
	if (result.type !== "success") {
		throw new Error(result.message);
	}

	const accountId = getAccountId(result.access);
	if (!accountId) {
		throw new Error("Failed to extract accountId from token");
	}

	return {
		access: result.access,
		refresh: result.refresh,
		expires: result.expires,
		accountId,
	};
}

export const openaiCodexOAuthProvider: OAuthProviderInterface = {
	id: "openai-codex",
	name: "ChatGPT Plus/Pro (Codex Subscription)",
	usesCallbackServer: true,

	async login(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
		let loginMethod = OPENAI_CODEX_BROWSER_LOGIN_METHOD;
		if (callbacks.onSelect) {
			const selected = await callbacks.onSelect({
				message: "Select OpenAI Codex login method:",
				options: [
					{ id: OPENAI_CODEX_BROWSER_LOGIN_METHOD, label: "Browser login (default)" },
					{ id: OPENAI_CODEX_DEVICE_CODE_LOGIN_METHOD, label: "Device code login (headless)" },
				],
			});
			if (!selected) {
				throw new Error("Login cancelled");
			}
			loginMethod = selected;
		}

		if (loginMethod === OPENAI_CODEX_DEVICE_CODE_LOGIN_METHOD) {
			if (!callbacks.onDeviceCode) {
				throw new Error("OpenAI Codex device code login requires a device code callback");
			}
			return loginOpenAICodexDeviceCode({
				onDeviceCode: callbacks.onDeviceCode,
				onProgress: callbacks.onProgress,
				signal: callbacks.signal,
			});
		}

		if (loginMethod !== OPENAI_CODEX_BROWSER_LOGIN_METHOD) {
			throw new Error(`Unknown OpenAI Codex login method: ${loginMethod}`);
		}

		return loginOpenAICodex({
			onAuth: callbacks.onAuth,
			onPrompt: callbacks.onPrompt,
			onProgress: callbacks.onProgress,
			onManualCodeInput: callbacks.onManualCodeInput,
		});
	},

	async refreshToken(credentials: OAuthCredentials): Promise<OAuthCredentials> {
		return refreshOpenAICodexToken(credentials.refresh);
	},

	getApiKey(credentials: OAuthCredentials): string {
		return credentials.access;
	},
};
