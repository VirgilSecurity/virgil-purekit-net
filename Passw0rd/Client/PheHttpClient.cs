// Copyright (C) 2015-2019 Virgil Security Inc.
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

namespace Passw0rd.Client
{
    using System.Net.Http;
    using System.Threading.Tasks;
    using Passw0rd.Client.Connection;
    using Passw0Rd;

    public class PheHttpClient : HttpClientBase, IPheHttpClient
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PheHttpClient"/> class.
        /// </summary>
        public PheHttpClient(IHttpBodySerializer serializer) : base(serializer)
        {
        }
        /// <summary>
        /// Send post request to enroll User Record.
        /// </summary>
        /// <returns>A new instance of the <see cref="EnrollmentResponse"/> class.</returns>
        /// <param name="request">An instance of the <see cref="EnrollmentRequest"/> class.</param>
        public async Task<EnrollmentResponse> GetEnrollment(EnrollmentRequest request){
            var response = await this.SendAsync<EnrollmentRequest, EnrollmentResponse>(
               HttpMethod.Post, $"phe/v1/enroll", request).ConfigureAwait(false);
            return response;
        }
     
        /// <summary>
        /// Send post request to Verify User Record.
        /// </summary>
        /// <returns>A new instance of the <see cref="VerifyPasswordResponse"/> class.</returns>
        /// <param name="request">An instance of the <see cref="VerifyPasswordRequest"/> class.</param>
        public async Task<VerifyPasswordResponse> VerifyAsync(VerifyPasswordRequest request)
        {
            var response = await this.SendAsync<VerifyPasswordRequest, VerifyPasswordResponse>(
                HttpMethod.Post, $"phe/v1/verify-password", request).ConfigureAwait(false);

            return response;
        }
    }
}
