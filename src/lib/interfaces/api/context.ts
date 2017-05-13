import {CookieJar, MemoryCookieStore, Store as CookieStore} from "tough-cookie";

/**
 * Represents the OAuth token used for most calls to the Skype API.
 */
export interface SkypeToken {
  value: string;
  expirationDate: Date;
}

export namespace SkypeToken {
  /**
   * JSON-safe representation of `SkypeToken`, used for serialization.
   */
  export interface Json {
    value: string;
    expirationDate: string;
  }

  /**
   * Export a SkypeToken to a JSON-safe object.
   */
  export function toJson(token: SkypeToken): SkypeToken.Json {
    return {
      value: token.value,
      expirationDate: token.expirationDate.toISOString(),
    };
  }

  /**
   * Import a SkypeToken from a JSON-safe object.
   */
  export function fromJson(token: SkypeToken.Json): SkypeToken {
    return {
      value: token.value,
      expirationDate: new Date(token.expirationDate),
    };
  }
}

/**
 * Represents the OAuth registration token. This token allows to subscribe to resources (receive messages).
 */
export interface RegistrationToken {
  value: string;
  expirationDate: Date;
  endpointId: string;
  host: string;
  raw: string;
}

export namespace RegistrationToken {
  /**
   * JSON-safe representation of `RegistrationToken`, used for serialization.
   */
  export interface Json {
    value: string;
    expirationDate: string;
    endpointId: string;
    host: string;
    raw: string;
  }

  /**
   * Export a RegistrationToken to a JSON-safe object.
   */
  export function toJson(token: RegistrationToken): RegistrationToken.Json {
    return {
      value: token.value,
      expirationDate: token.expirationDate.toISOString(),
      endpointId: token.endpointId,
      host: token.host,
      raw: token.raw,
    };
  }

  /**
   * Import a RegistrationToken from a JSON-safe object.
   */
  export function fromJson(token: RegistrationToken.Json): RegistrationToken {
    return {
      value: token.value,
      expirationDate: new Date(token.expirationDate),
      endpointId: token.endpointId,
      host: token.host,
      raw: token.raw,
    };
  }
}

/**
 * API context (state).
 */
// TODO(demurgos): Rename to `State` or even `ApiState` so it's easier to understand the purpose of this interface.
export interface Context {
  username: string;
  cookies: CookieStore;
  skypeToken: SkypeToken;
  registrationToken?: RegistrationToken;
}

export namespace Context {
  /**
   * JSON-safe representation of `Context`.
   */
  export interface Json {
    username: string;
    cookies: Object;
    skypeToken: SkypeToken.Json;
    registrationToken?: RegistrationToken.Json;
  }

  export function toJson(context: Context): Context.Json {
    return {
      username: context.username,
      cookies: new CookieJar(context.cookies).serializeSync(),
      skypeToken: SkypeToken.toJson(context.skypeToken),
      registrationToken: context.registrationToken && RegistrationToken.toJson(context.registrationToken),
    };
  }

  export function fromJson(context: Context.Json): Context {
    const cookies: MemoryCookieStore = new MemoryCookieStore();
    CookieJar.deserializeSync(context.cookies, cookies);

    return {
      username: context.username,
      cookies,
      skypeToken: SkypeToken.fromJson(context.skypeToken),
      registrationToken: context.registrationToken && RegistrationToken.fromJson(context.registrationToken),
    };
  }
}
