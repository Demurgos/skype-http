import {Incident} from "incident";
import * as api from "../interfaces/api/api";
import {Context} from "../interfaces/api/context";
import * as io from "../interfaces/http-io";
import * as messagesUri from "../messages-uri";
import {registerEndpoint} from "./register-endpoint";

interface RequestBody {
  status: string;
}

export async function setStatus(io: io.HttpIo, apiContext: Context, status: api.Status): Promise<void> {
  if (apiContext.registrationToken === undefined) {
    apiContext.registrationToken = await registerEndpoint(io, apiContext);
  }

  const requestBody: RequestBody = {
    status: status,
  };
  const requestOptions: io.PostOptions = {
    uri: messagesUri.userMessagingService(apiContext.registrationToken.host),
    cookies: apiContext.cookies,
    body: JSON.stringify(requestBody),
    headers: {
      RegistrationToken: apiContext.registrationToken.raw,
    },
  };
  const res: io.Response = await io.put(requestOptions);

  if (res.statusCode !== 200) {
    return Promise.reject(new Incident("send-message", "Received wrong return code"));
  }
}

export default setStatus;
