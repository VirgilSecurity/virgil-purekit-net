// Copyright (C) 2015-2018 Virgil Security Inc.
// 
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions 
// are met:
// 
//   (1) Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//   
//   (2) Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in
//   the documentation and/or other materials provided with the
//   distribution.
//   
//   (3) Neither the name of the copyright holder nor the names of its
//   contributors may be used to endorse or promote products derived 
//   from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

namespace Passw0rd.Client.Connection
{
    using System;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;

    public class HttpClientBase
    {
        private readonly IHttpBodySerializer serializer;

        private HttpClient client;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpClientBase"/> class.
        /// </summary>
        protected HttpClientBase(IHttpBodySerializer serializer)
        {
            this.serializer = serializer;
            this.client = new HttpClient();
        }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public string AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the base URI.
        /// </summary>
        public Uri BaseUri { get; set; }

        protected async Task<TResponseModel> SendAsync<TRequestModel, TResponseModel>(HttpMethod method, string endpoint, TRequestModel body)
        {
            Uri endpointUri = this.BaseUri != null
                                  ? new Uri(this.BaseUri, endpoint)
                                  : new Uri(endpoint);

            var request = new HttpRequestMessage(method, endpointUri);

            if (!string.IsNullOrWhiteSpace(this.AccessToken))
            {
                request.Headers.TryAddWithoutValidation("Authorization", $"{this.AccessToken}");
            }

            if (method != HttpMethod.Get)
            {
                var serializedBody = this.serializer.Serialize(body);
                request.Content = new StringContent(serializedBody, Encoding.UTF8, "application/json");
            }

            var response = await this.client.SendAsync(request).ConfigureAwait(false);
            var content = await response.Content.ReadAsStringAsync();

            this.HandleError(response.StatusCode, content);

            var model = this.serializer.Deserialize<TResponseModel>(content);

            return model;
        }

        protected async Task<TResponseModel> SendAsync<TResponseModel>(HttpMethod method, string endpoint)
        {
            Uri endpointUri = this.BaseUri != null
                                  ? new Uri(this.BaseUri, endpoint)
                                  : new Uri(endpoint);

            var request = new HttpRequestMessage(method, endpointUri);

            if (!string.IsNullOrWhiteSpace(this.AccessToken))
            {
                request.Headers.TryAddWithoutValidation("Authorization", $"{this.AccessToken}");
            }

            var response = await this.client.SendAsync(request).ConfigureAwait(false);
            var content = await response.Content.ReadAsStringAsync();

            this.HandleError(response.StatusCode, content);

            var model = this.serializer.Deserialize<TResponseModel>(content);

            return model;
        }

        private void HandleError(HttpStatusCode statusCode, string body)
        {
            string errorMessage;

            switch (statusCode)
            {
                case HttpStatusCode.OK: // OK
                case HttpStatusCode.Created: // Created
                case HttpStatusCode.Accepted: // Accepted
                case HttpStatusCode.NonAuthoritativeInformation: // Non-Authoritative Information
                case HttpStatusCode.NoContent: // No Content
                    return;

                case HttpStatusCode.BadRequest: errorMessage = "Request Error"; break;
                case HttpStatusCode.Unauthorized: errorMessage = "Authorization Error"; break;
                case HttpStatusCode.NotFound: errorMessage = "Entity Not Found"; break;
                case HttpStatusCode.MethodNotAllowed: errorMessage = "Method Not Allowed"; break;
                case HttpStatusCode.InternalServerError: errorMessage = "Internal Server Error"; break;

                default:
                    errorMessage = $"Undefined Exception (Http Status Code: {statusCode})";
                    break;
            }

            var errorCode = 0;

            if (!string.IsNullOrWhiteSpace(body))
            {
                var error = serializer.Deserialize<ServiceErrorModel>(body);

                errorCode = error?.ErrorCode ?? 0;
                if (error != null && error.Message != null)
                {
                    errorMessage += $": {error.Message}";
                }
            }

            throw new ServiceClientException(errorCode, errorMessage);
        }
    }
}