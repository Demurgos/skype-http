import {EventEmitter} from "events";
import {Incident} from "incident";
import {registerEndpoint} from "../api/register-endpoint";
import {UnexpectedHttpStatusError} from "../errors/http";
import {ParsedConversationId} from "../interfaces/api/api";
import {Context as ApiContext} from "../interfaces/api/context";
import * as events from "../interfaces/api/events";
import * as resources from "../interfaces/api/resources";
import * as httpIo from "../interfaces/http-io";
import * as nativeEvents from "../interfaces/native-api/events";
import * as nativeMessageResources from "../interfaces/native-api/message-resources";
import * as nativeResources from "../interfaces/native-api/resources";
import * as messagesUri from "../messages-uri";

// Perform one request every 1000 ms
const POLLING_DELAY: number = 1000;

// Match a contact id:
// TODO: handle the "guest" prefix
const CONTACT_ID_PATTERN: RegExp = /^(\d+):(.+)$/;

// TODO(demurgos): Looks like there is a problem with the return type
export function parseContactId(contactId: string): ParsedConversationId {
  const match: RegExpExecArray | null = CONTACT_ID_PATTERN.exec(contactId);
  if (match === null) {
    throw new Incident("parse-error", "Unable to parse userId");
  }
  return {
    raw: contactId,
    prefix: parseInt(match[1], 10),
    username: match[2],
  };
}

export function formatRichTextResource(nativeResource: nativeMessageResources.RichText): resources.RichTextResource {
  const parsedConversationUri: messagesUri.ConversationUri = messagesUri
    .parseConversation(nativeResource.conversationLink);
  const parsedContactUri: messagesUri.ContactUri = messagesUri.parseContact(nativeResource.from);
  const parsedContactId: ParsedConversationId = parseContactId(parsedContactUri.contact);
  return {
    type: "RichText",
    id: nativeResource.id,
    clientId: nativeResource.clientmessageid,
    composeTime: new Date(nativeResource.composetime),
    arrivalTime: new Date(nativeResource.originalarrivaltime),
    from: parsedContactId,
    conversation: parsedConversationUri.conversation,
    content: nativeResource.content,
  };
}

export function formatTextResource(nativeResource: nativeMessageResources.Text): resources.TextResource {
  const parsedConversationUri: messagesUri.ConversationUri = messagesUri
    .parseConversation(nativeResource.conversationLink);
  const parsedContactUri: messagesUri.ContactUri = messagesUri.parseContact(nativeResource.from);
  const parsedContactId: ParsedConversationId = parseContactId(parsedContactUri.contact);
  return {
    type: "Text",
    id: nativeResource.id,
    clientId: nativeResource.clientmessageid,
    composeTime: new Date(nativeResource.composetime),
    arrivalTime: new Date(nativeResource.originalarrivaltime),
    from: parsedContactId,
    conversation: parsedConversationUri.conversation,
    content: nativeResource.content,
  };
}

// tslint:disable-next-line:max-line-length
export function formatControlClearTypingResource(nativeResource: nativeMessageResources.ControlClearTyping): resources.ControlClearTypingResource {
  const parsedConversationUri: messagesUri.ConversationUri = messagesUri
    .parseConversation(nativeResource.conversationLink);
  const parsedContactUri: messagesUri.ContactUri = messagesUri.parseContact(nativeResource.from);
  const parsedContactId: ParsedConversationId = parseContactId(parsedContactUri.contact);
  return {
    type: "Control/ClearTyping",
    id: nativeResource.id,
    composeTime: new Date(nativeResource.composetime),
    arrivalTime: new Date(nativeResource.originalarrivaltime),
    from: parsedContactId,
    conversation: parsedConversationUri.conversation,
    native: nativeResource,
  };
}

// tslint:disable-next-line:max-line-length
export function formatControlTypingResource(nativeResource: nativeMessageResources.ControlTyping): resources.ControlTypingResource {
  const parsedConversationUri: messagesUri.ConversationUri = messagesUri
    .parseConversation(nativeResource.conversationLink);
  const parsedContactUri: messagesUri.ContactUri = messagesUri.parseContact(nativeResource.from);
  const parsedContactId: ParsedConversationId = parseContactId(parsedContactUri.contact);
  return {
    type: "Control/Typing",
    id: nativeResource.id,
    composeTime: new Date(nativeResource.composetime),
    arrivalTime: new Date(nativeResource.originalarrivaltime),
    from: parsedContactId,
    conversation: parsedConversationUri.conversation,
    native: nativeResource,
  };
}

function formatMessageResource(nativeResource: nativeResources.MessageResource): resources.Resource {
  switch (nativeResource.messagetype) {
    case "RichText":
      return formatRichTextResource(<nativeMessageResources.RichText> nativeResource);
    case "Text":
      return formatTextResource(<nativeMessageResources.Text> nativeResource);
    case "Control/ClearTyping":
      return formatControlClearTypingResource(<nativeMessageResources.ControlClearTyping> nativeResource);
    case "Control/Typing":
      return formatControlTypingResource(<nativeMessageResources.ControlTyping> nativeResource);
    default:
      // tslint:disable-next-line:max-line-length
      throw new Error(`Unknown ressource.messageType (${JSON.stringify(nativeResource.messagetype)}) for resource:\n${JSON.stringify(nativeResource)}`);
  }
}

function formatEventMessage(native: nativeEvents.EventMessage): events.EventMessage {
  let resource: resources.Resource | null;
  switch (native.resourceType) {
    case "UserPresence":
      resource = null;
      break;
    case "EndpointPresence":
      resource = null;
      break;
    case "NewMessage":
      resource = formatMessageResource(<nativeResources.MessageResource> native.resource);
      break;
    default:
      // tslint:disable-next-line:max-line-length
      throw new Error(`Unknown EventMessage.resourceType (${JSON.stringify(native.resourceType)}) for Event:\n${JSON.stringify(native)}`);
  }

  return {
    id: native.id,
    type: native.type,
    resourceType: native.resourceType,
    time: new Date(native.time),
    resourceLink: native.resourceLink,
    resource: resource,
  };
}

export class MessagesPoller extends EventEmitter {
  io: httpIo.HttpIo;
  apiContext: ApiContext;
  intervalId: number | NodeJS.Timer | null;

  constructor(io: httpIo.HttpIo, apiContext: ApiContext) {
    super();

    this.io = io;
    this.apiContext = apiContext;
    this.intervalId = null;
  }

  isActive(): boolean {
    return this.intervalId !== null;
  }

  run(): this {
    if (this.isActive()) {
      return this;
    }
    this.intervalId = setInterval(this.getMessages.bind(this), POLLING_DELAY);
    return this;
  }

  stop(): this {
    if (!this.isActive()) {
      return this;
    }
    clearInterval(<any> this.intervalId);
    this.intervalId = null;
    return this;
  }

  /**
   * Get the new messages / events from the server.
   * This function always returns a successful promise once the messages are retrieved or an error happens.
   *
   * If any error happens, the message-poller will emit an `error` event with the error.
   */
  protected async getMessages(): Promise<void> {
    try {
      if (this.apiContext.registrationToken === undefined) {
        this.apiContext.registrationToken = await registerEndpoint(this.io, this.apiContext);
      }

      const requestOptions: httpIo.PostOptions = {
        // TODO: explicitly define user, endpoint and subscription
        uri: messagesUri.poll(this.apiContext.registrationToken.host),
        cookies: this.apiContext.cookies,
        headers: {
          RegistrationToken: this.apiContext.registrationToken.raw,
        },
      };
      const res: httpIo.Response = await this.io.post(requestOptions);

      if (res.statusCode !== 200) {
        const cause: UnexpectedHttpStatusError = UnexpectedHttpStatusError.create(res, new Set([200]), requestOptions);
        this.emit("error", Incident(cause, "poll", "Unable to poll the messages"));
        return;
      }

      const body: {eventMessages?: nativeEvents.EventMessage[]} = JSON.parse(res.body);

      if (body.eventMessages) {
        for (const msg of body.eventMessages) {
          const formatted: events.EventMessage = formatEventMessage(msg);
          if (formatted && formatted.resource) {
            this.emit("event-message", formatted);
          }
        }
      }
    } catch (err) {
      this.emit("error", Incident(err, "poll", "An error happened while processing the polled messages"));
    }
  }
}

export default MessagesPoller;
