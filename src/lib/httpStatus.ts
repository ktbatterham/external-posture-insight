export interface HttpStatusDetails {
  label: string;
  meaning: string;
}

export const getHttpStatusDetails = (statusCode: number): HttpStatusDetails => {
  const knownStatuses: Record<number, string> = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
  };

  const meaningByStatus: Record<number, string> = {
    200: "The page responded normally and the scan reflects the site's current public response.",
    201: "The server reports a successful resource creation response.",
    204: "The server accepted the request but returned no page content.",
    301: "The site permanently redirects this URL to another location.",
    302: "The site temporarily redirects this URL before serving content.",
    303: "The server is redirecting the client to a different resource.",
    307: "The site redirected the request temporarily while preserving the method.",
    308: "The site redirected the request permanently while preserving the method.",
    400: "The server rejected the request as malformed or unacceptable.",
    401: "The target expects authentication before it will return the resource.",
    403: "The server understood the request but refused to serve the page.",
    404: "The requested page was not found at the scanned URL.",
    405: "The site does not allow the HTTP method used for this request.",
    408: "The server took too long and timed out the request.",
    429: "The site is rate-limiting requests from the scanner.",
    500: "The site hit an internal error while trying to serve the page.",
    502: "An upstream gateway or proxy returned an invalid response.",
    503: "The service appears temporarily unavailable or overloaded.",
    504: "A gateway or proxy timed out while waiting on the upstream service.",
  };

  let label = knownStatuses[statusCode];
  if (!label) {
    if (statusCode >= 200 && statusCode < 300) label = "Successful response";
    else if (statusCode >= 300 && statusCode < 400) label = "Redirect response";
    else if (statusCode >= 400 && statusCode < 500) label = "Client error";
    else if (statusCode >= 500) label = "Server error";
    else label = "Unknown status";
  }

  let meaning = meaningByStatus[statusCode];
  if (!meaning) {
    if (statusCode >= 200 && statusCode < 300) meaning = "The target returned a successful HTTP response.";
    else if (statusCode >= 300 && statusCode < 400) meaning = "The scanner reached the target through one or more redirects.";
    else if (statusCode >= 400 && statusCode < 500) {
      meaning = "The target refused or could not satisfy the request from the client side.";
    } else if (statusCode >= 500) {
      meaning = "The target encountered a server-side problem while serving the request.";
    } else {
      meaning = "The scanner received a response code that does not map cleanly to a standard explanation.";
    }
  }

  return { label, meaning };
};
