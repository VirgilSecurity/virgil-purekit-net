#pragma warning disable SA1633 // FileMustHaveHeader
/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Passw0rd
{
    using Google.Protobuf;
    using Passw0rd.Utils;

    public class RecordUpdater
    {
        /// <summary>
        /// Gets the PHE Client instanse.
        /// </summary>
        private PheClient pheClient;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:Passw0rd.RecordUpdater"/> class.
        /// </summary>
        /// <param name="token">Update token to be used for updating user's record.
        /// How to generate Update Token you will find
        /// <see href="https://github.com/passw0rd/cli#get-an-update-token">here</see>.</param>
        public RecordUpdater(string token)
        {
            Validation.NotNullOrWhiteSpace(token, "UpdateToken isn't provided.");
            this.VersionedUpdateToken = StringUpdateTokenParser.Parse(token);
            this.pheClient = new PheClient();
        }

        /// <summary>
        /// Gets the VersionedUpdateToken instanse.
        /// </summary>
        public VersionedUpdateToken VersionedUpdateToken { get; private set; }

        /// <summary>
        /// Update the specified Encrypted Passw0rd's record.
        /// </summary>
        /// <returns>The updated Encrypted Passw0rd's record.</returns>
        /// <param name="oldPwdRecord">Old Passw0rd's record.</param>
        public byte[] Update(byte[] oldPwdRecord)
        {
            Validation.NotNullOrEmptyByteArray(oldPwdRecord, "Record isn't provided.");

            var databaseRecord = DatabaseRecord.Parser.ParseFrom(oldPwdRecord);

            if (databaseRecord.Version == this.VersionedUpdateToken.Version)
            {
                throw new WrongVersionException(
                    string.Format("Record can't be updated with the same version"));
            }

            if (databaseRecord.Version + 1 == this.VersionedUpdateToken.Version)
            {
                var updatedEnrollmentRecordData = this.pheClient.UpdateEnrollmentRecord(
                    this.VersionedUpdateToken.UpdateToken.ToByteArray(),
                    databaseRecord.Record.ToByteArray());

                var updatedDatabaseRecord = new DatabaseRecord
                {
                    Version = this.VersionedUpdateToken.Version,
                    Record = ByteString.CopyFrom(updatedEnrollmentRecordData),
                };
                return updatedDatabaseRecord.ToByteArray();
            }

            throw new WrongVersionException(
                string.Format(
                    "Record and update token versions mismatch: {0} and {1}",
                    databaseRecord.Version,
                    this.VersionedUpdateToken.Version));
        }
    }
}
