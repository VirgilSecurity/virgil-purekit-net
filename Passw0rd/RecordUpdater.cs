using System;
using Google.Protobuf;
using Passw0rd.Phe;
using Passw0Rd;
namespace Passw0rd
{
    public class RecordUpdater
    {
        public VersionedUpdateToken VersionedUpdateToken {get; private set;}
        public PheCrypto PheCrypto { get; private set; }
        public RecordUpdater(string token)
        {
            Validation.NotNullOrWhiteSpace(token, "UpdateToken isn't provided.");
            this.VersionedUpdateToken = StringUpdateTokenParser.Parse(token);
            this.PheCrypto = new PheCrypto();
        }

        /// <summary>
        /// Updates a <see cref="DatabaseRecord"/> with an specified <see cref="VersionedUpdateToken"/>.
        /// </summary>
        public byte[] Update(byte[] oldPwdRecord){
            Validation.NotNullOrEmptyByteArray(oldPwdRecord, "Record isn't provided.");

            var databaseRecord = DatabaseRecord.Parser.ParseFrom(oldPwdRecord);

            if (databaseRecord.Version == VersionedUpdateToken.Version)
            {
                throw new WrongVersionException(
                    String.Format("Record can't be updated with the same version"));
            }

            if (databaseRecord.Version + 1 == VersionedUpdateToken.Version)
            {
                var enrollmentRecord = EnrollmentRecord.Parser.ParseFrom(databaseRecord.Record);

               // var t0 = enrollmentRecord.T0.ToByteArray();
               // var t1 = enrollmentRecord.T1.ToByteArray();
                var (t0, t1) = PheCrypto.UpdateT(enrollmentRecord.Ns.ToByteArray(),
                                              enrollmentRecord.T0.ToByteArray(),
                                              enrollmentRecord.T1.ToByteArray(),
                                              VersionedUpdateToken.UpdateToken.ToByteArray());

                var updatedEnrollmentRecord = new EnrollmentRecord
                {
                    Nc = enrollmentRecord.Nc,
                    Ns = enrollmentRecord.Ns,
                    T0 = ByteString.CopyFrom(t0),
                    T1 = ByteString.CopyFrom(t1)
                };

                var updatedDatabaseRecord = new DatabaseRecord
                {
                    Version = VersionedUpdateToken.Version,
                    Record = ByteString.CopyFrom(updatedEnrollmentRecord.ToByteArray())
                };
                return updatedDatabaseRecord.ToByteArray();
            }

            throw new WrongVersionException(
                String.Format("Record and update token versions mismatch: {0} and {1}",
                              databaseRecord.Version, VersionedUpdateToken.Version)
            );
        }
    }
}
