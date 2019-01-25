using System;
using Google.Protobuf;
using Passw0rd.Phe;
using Passw0Rd;
using Phe;

namespace Passw0rd
{
    public class RecordUpdater
    {
        public VersionedUpdateToken UpdateToken {get; private set;}
        public PheCrypto PheCrypto { get; private set; }
        public RecordUpdater(string token)
        {
            if (token == null)
            {
                throw new ArgumentNullException("UpdateToken is not provided in context");
            }
            this.UpdateToken = StringUpdateTokenParser.Parse(token);
            this.PheCrypto = new PheCrypto();
        }

        /// <summary>
        /// Updates a <see cref="DatabaseRecord"/> with an specified <see cref="VersionedUpdateToken"/>.
        /// </summary>
        public byte[] Update(byte[] oldPwdRecord){

            if (oldPwdRecord == null)
            {
                throw new ArgumentNullException(nameof(oldPwdRecord));
            }


            var databaseRecord = DatabaseRecord.Parser.ParseFrom(oldPwdRecord);

            if (databaseRecord.Version == UpdateToken.Version)
            {
                throw new WrongVersionException(
                    String.Format("Record can't be updated with the same version"));
            }

            if (databaseRecord.Version + 1 == UpdateToken.Version)
            {
                var enrollmentRecord = EnrollmentRecord.Parser.ParseFrom(databaseRecord.Record);

               // var t0 = enrollmentRecord.T0.ToByteArray();
               // var t1 = enrollmentRecord.T1.ToByteArray();
                var (t0, t1) = PheCrypto.UpdateT(enrollmentRecord.Ns.ToByteArray(),
                                              enrollmentRecord.T0.ToByteArray(),
                                              enrollmentRecord.T1.ToByteArray(),
                                              UpdateToken.ToByteArray());


                var updatedEnrollmentRecord = new EnrollmentRecord
                {
                    Nc = enrollmentRecord.Nc,
                    Ns = enrollmentRecord.Ns,
                    T0 = ByteString.CopyFrom(t0),
                    T1 = ByteString.CopyFrom(t1)
                };

                var updatedDatabaseRecord = new DatabaseRecord
                {
                    Version = UpdateToken.Version,
                    Record = ByteString.CopyFrom(updatedEnrollmentRecord.ToByteArray())

                };
                return updatedDatabaseRecord.ToByteArray();
            }

            throw new WrongVersionException(
                String.Format("Record and update token versions mismatch: {0} and {1}",
                              databaseRecord.Version, UpdateToken.Version)
            );
        }
    }
}
