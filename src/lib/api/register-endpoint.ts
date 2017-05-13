import {Incident} from "incident";
import {parse as parseUri, Url} from "url";
import * as Consts from "../consts";
import {UnexpectedHttpStatusError} from "../errors/http";
import {Context, RegistrationToken} from "../interfaces/api/context";
import * as io from "../interfaces/http-io";
import {Dictionary} from "../interfaces/utils";
import * as messagesUri from "../messages-uri";
import {getCurrentTime, parseHeaderParams, stringifyHeaderParams} from "../utils";
import {hmacSha256} from "../utils/hmac-sha256";

function getLockAndKeyResponse(time: number): string {
  const inputBuffer: Buffer = Buffer.from(String(time), "utf8");
  const appIdBuffer: Buffer = Buffer.from(Consts.SKYPEWEB_LOCKANDKEY_APPID, "utf8");
  const secretBuffer: Buffer = Buffer.from(Consts.SKYPEWEB_LOCKANDKEY_SECRET, "utf8");
  return hmacSha256(inputBuffer, appIdBuffer, secretBuffer);
}

export interface RegisterEndpointOptions {
  /**
   * Default: Consts.SKYPEWEB_DEFAULT_MESSAGES_HOST
   */
  messagesHost?: string;
  /**
   * Default: 2
   */
  retry?: number;
}

/**
 * Register the endpoint and aquire a new registration token.
 */
export async function registerEndpoint(
  io: io.HttpIo,
  apiContext: Context,
  options?: RegisterEndpointOptions,
): Promise<RegistrationToken> {
  const startTime: number = getCurrentTime();
  const lockAndKeyResponse: string = getLockAndKeyResponse(startTime);
  const headers: Dictionary<string> = {
    LockAndKey: stringifyHeaderParams({
      appId: Consts.SKYPEWEB_LOCKANDKEY_APPID,
      time: String(startTime),
      lockAndKeyResponse: lockAndKeyResponse,
    }),
    ClientInfo: stringifyHeaderParams({
      os: "Windows",
      osVer: "10",
      proc: "Win64",
      lcid: "en-us",
      deviceType: "1",
      country: "n/a",
      clientName: Consts.SKYPEWEB_CLIENTINFO_NAME,
      clientVer: Consts.SKYPEWEB_CLIENTINFO_VERSION,
    }),
    Authentication: stringifyHeaderParams({
      skypetoken: apiContext.skypeToken.value,
    }),
  };

  const messagesHost: string = options === undefined || options.messagesHost === undefined
    ? Consts.SKYPEWEB_DEFAULT_MESSAGES_HOST
    : options.messagesHost;

  const requestOptions: io.PostOptions = {
    uri: messagesUri.endpoints(messagesHost),
    headers: headers,
    cookies: apiContext.cookies,
    body: "{}", // Skype requires you to send an empty object as a body
  };

  const res: io.Response = await io.post(requestOptions);
  const expectedStatusCodes: Set<number> = new Set([201, 301]);

  if (!expectedStatusCodes.has(res.statusCode)) {
    throw UnexpectedHttpStatusError.create(res, expectedStatusCodes, requestOptions);
  }

  const locationHeader: string = res.headers["location"];

  const location: Url = parseUri(locationHeader); // TODO: parse in messages-uri.ts
  if (location.host === undefined) {
    throw new Incident("UndefinedLocationHost", {response: res}, "Expected the `location` header to define host");
  }
  if (location.host !== messagesHost) { // mainly when 301, but sometimes when 201
    const retry: number = options === undefined || options.retry === undefined ? 2 : options.retry;
    if (retry > 0) {
      return registerEndpoint(io, apiContext, {messagesHost: location.host, retry});
    } else {
      return Promise.reject(new Incident("net", "Exceeded max tries"));
    }
  }

// registrationTokenHeader is like "registrationToken=someString; expires=someNumber; endpointId={someString}"
  const registrationTokenHeader: string = res.headers["set-registrationtoken"];
  const parsedHeader: Dictionary<string> = parseHeaderParams(registrationTokenHeader);

  if (!parsedHeader["registrationToken"] || !parsedHeader["expires"] || !parsedHeader["endpointId"]) {
    return Promise.reject(new Incident("protocol", "Missing parameters for the registrationToken"));
  }

  const expires: number = parseInt(parsedHeader["expires"], 10); // in seconds

  return {
    value: parsedHeader["registrationToken"],
    expirationDate: new Date(1000 * expires),
    endpointId: parsedHeader["endpointId"],
    raw: registrationTokenHeader,
    host: messagesHost,
  };
}
