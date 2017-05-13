import {Incident} from "incident";
import * as _ from "lodash";
import {Context} from "../interfaces/api/context";
import {Conversation} from "../interfaces/api/conversation";
import * as io from "../interfaces/http-io";
import {Conversation as NativeConversation} from "../interfaces/native-api/conversation";
import * as messagesUri from "../messages-uri";
import {formatConversation} from "../utils/formatters";
import {registerEndpoint} from "./register-endpoint";

interface ConversationsBody {
  conversations: NativeConversation[];
  _metadata: {
    totalCount: number;
    forwardLink: string; // url
    backwardLink: string; // url
    syncState: string; // url
  };
}

interface GetConversationsQuery {
  startTime: number; // a timestamp ?
  view: "msnp24Equivalent" | string;
  targetType: string; // seen: Passport|Skype|Lync|Thread
}

export async function getConversations(io: io.HttpIo, apiContext: Context): Promise<Conversation[]> {
  if (apiContext.registrationToken === undefined) {
    apiContext.registrationToken = await registerEndpoint(io, apiContext);
  }

  const query: GetConversationsQuery = {
    startTime: 0,
    view: "msnp24Equivalent",
    targetType: "Passport|Skype|Lync|Thread",
  };

  const requestOptions: io.GetOptions = {
    uri: messagesUri.conversations(apiContext.registrationToken.host, messagesUri.DEFAULT_USER),
    cookies: apiContext.cookies,
    queryString: query,
    headers: {
      RegistrationToken: apiContext.registrationToken.raw,
    },
  };
  const res: io.Response = await io.get(requestOptions);

  if (res.statusCode !== 200) {
    return Promise.reject(new Incident("net", "Unable to fetch conversations"));
  }
  const body: ConversationsBody = JSON.parse(res.body);
  return _.map(body.conversations, formatConversation);
}

export default getConversations;
