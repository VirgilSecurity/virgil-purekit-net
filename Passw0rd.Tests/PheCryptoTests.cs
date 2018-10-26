namespace Passw0rd.Tests
{
    using System;

    using Passw0rd.Phe;
    using Passw0rd.Utils; 

    using Xunit;
    using Xunit.Abstractions;

    public class PheCryptoTests
    {
        private readonly ITestOutputHelper output;

        public PheCryptoTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void Should_ComputeIdenticalC0AndC1Values_When_TheSameKeyAndNonceArePassed()
        {
            var phe = new PheCrypto();

            var skS = phe.DecodeSecretKey(Bytes.FromString("I4ETKFzr3QmUu+Olhp1L2KvRgjfseO530R/A+aQ80Go=", StringEncoding.BASE64));
            var nS = Bytes.FromString("4g1N7hTxVWEHesoGZ5eTwbufdSnRtzxzkEQaBkXWsL4=", StringEncoding.BASE64);
            var c0 = Bytes.FromString("BI4mieAp/rdVctneZnhj0Ucu8Sc4LGMu2P5z9j49iXtN3AhDBWgIS1A4kfLI1ktcQAJACK4vwgutomtuWSoYllc=", StringEncoding.BASE64);
            var c1 = Bytes.FromString("BHENDFDcDsaWwpZLAWXDvEXlrEpIwr1p+OESiRCSemnk41WdfObVsvGPsYNFopaCJN762vP4MINb9HGzjmbM+aU=", StringEncoding.BASE64);

            var (c00, c11) = phe.ComputeC(skS, nS);

            Assert.Equal(c0, c00);
            Assert.Equal(c1, c11);
        }

        [Fact]
        public void Should_ComputeTheSameC0Value_For_SpecifiedListOfParameters()
        {
            var phe = new PheCrypto();

            var pwd = Bytes.FromString("passw0rd");
            var skC = phe.DecodeSecretKey(Bytes.FromString("gPdKsQRz9Vmc/DnbfxCHUioU6omEa0Sg7pncSHOhA7I=", StringEncoding.BASE64));
            var nC = Bytes.FromString("CTnPcIn2xcz+4/9jjLuFZNJiWLBiohnaGVTb3X1zPt0=", StringEncoding.BASE64);
            var c0 = Bytes.FromString("BKAH5Rww+a9+8lzO3oYE8zfz2Oxp3+Xrv2jp9EFGRlS7bWU5iYoWQHZqrkM+UYq2TYON3Gz8w3mzLSy3yS0XlJw=", StringEncoding.BASE64);
            var t0 = Bytes.FromString("BPGwrvLl3CAolVo1RIoNT7TqTC3T66eLykxa/Vw1gyof+3scfaiqTAAQXQ57q6zEkEeJHjNl4GBghQceI/UNl7c=", StringEncoding.BASE64);

            var c00 = phe.ComputeC0(skC, pwd, nC, t0);

            Assert.Equal(c0, c00);
        }

        [Fact]
        public void Should_ProveTheProofOfSuccess_For_SpecifiedListOfParameters()
        {
            var phe   = new PheCrypto();

            var skS   = phe.DecodeSecretKey(Bytes.FromString("I4ETKFzr3QmUu+Olhp1L2KvRgjfseO530R/A+aQ80Go=", StringEncoding.BASE64));
            var c0    = Bytes.FromString("BKAH5Rww+a9+8lzO3oYE8zfz2Oxp3+Xrv2jp9EFGRlS7bWU5iYoWQHZqrkM+UYq2TYON3Gz8w3mzLSy3yS0XlJw=", StringEncoding.BASE64);
            var c1    = Bytes.FromString("BOkgpxdavc+CYqmeKboBPhEjgXCEKbb5HxFeJ1+rVoOm006Jbu5a/Ol4rK5bVbkhzGAT+gUZaodUsnEuucfIbJc=", StringEncoding.BASE64);

            var proof = new ProofOfSuccess
            {
                Term1 = Bytes.FromString("BJkkIassffljoINliNRNcR7J/PmYcAl9PPUBeIT2I6oBy6wKb5gZsIOchWEN5pNfLVPH1V0BuhhlTi7MZeBlPOY=", StringEncoding.BASE64),
                Term2 = Bytes.FromString("BIiZfmmzuffwmJmibNnpws9D5SkgkPMBYxbgaWS1274kbJKC7WakUp1Mzk9BWvah0kDomJhqzyV7/8ZBX1rGX9I=", StringEncoding.BASE64),
                Term3 = Bytes.FromString("BCBcx9GsjQcoKI0pW4t49WWS/Z1bmg62KlCjAzB1IsKVDYQAT4213UuIMBthNnxSOVUUHikZCUw01mX5XKGQD5A=", StringEncoding.BASE64),
                BlindX = Bytes.FromString("KFiLnVVliWdm3fdYcuFK1sTiw1hvbKSesy4sGlYO8Rs=", StringEncoding.BASE64)
            };

            var skC = phe.DecodeSecretKey(Bytes.FromString("gPdKsQRz9Vmc/DnbfxCHUioU6omEa0Sg7pncSHOhA7I=", StringEncoding.BASE64));

            var nS  = Bytes.FromString("POKVRG0nmZc9062v41TNFngibsgMKzt/BY6lZ/5pcZg=", StringEncoding.BASE64);

            var isValid = phe.ValidateProofOfSuccess(proof, skS.PublicKey, nS, c0, c1);

            Assert.True(isValid);
        }

        [Fact]
        public void Should_ProveTheProofOfFail_When_SpecifiedListOfParametersArePassed()
        {
            var phe = new PheCrypto();

            var pkS = phe.DecodePublicKey(Bytes.FromString("BBVbS+bzzP5v7HxBs7p41HJT7mDuC8w5XcSsDMRmr/4fsH4mAFBkgcFrJ8kNqL1O5/BsTVp1eSn/vLlAZ6nMJM0=", StringEncoding.BASE64));
            var nS  = Bytes.FromString("bkVqMplyydZjQxo8R0EtODHEOqTfl02j8T5ZOa0tRnw=", StringEncoding.BASE64);
            var c0  = Bytes.FromString("BC5NNsFoaiMN1Flo/qPAzb0peVZSTJabpGR/ZW8y8t2iwqrJyQ7XiJfPzTFVGbDTbpF2NZOYJyoy8yWcu0ej/pk=", StringEncoding.BASE64);
            var c1  = Bytes.FromString("BA3VawoS0AHkkoqvdoAQY+Rny76K5qJGBXI6HPYpar9v1VQA4PXoHW7uWECW8ulljYMtP06696JcNmQTsjYmDdk=", StringEncoding.BASE64);

            var proof = new ProofOfFail
            {
                Term1  = Bytes.FromString("BEY086yK/21rcM/L1o1VlgFbG543aHd5wsSz149MAqsE9PjKOkBlLgo4L8erUZkyW9rnJlVy2OlppjJ5ti17JXs=", StringEncoding.BASE64),
                Term2  = Bytes.FromString("BGB1gW1fJAJZKIicx5BBoGjCvsA29FONmVZ9KJQYB1pQoTRvz4LuF1m6BB7e1HtT58piuk8ZxHFqF4gmEDbTUiU=", StringEncoding.BASE64),
                Term3  = Bytes.FromString("BPgnI6MoiihA1C/VdfvFN1f4nEd9Cvh5Mp4fRppYsOXjUBuB70jNlLq02DHLqlkcASEsL0wORH7LZbTqUdaEKgY=", StringEncoding.BASE64),
                Term4  = Bytes.FromString("BFlUCX9E6QOpxxJOWuGhPujJOuJdVKFaU1C8aSyiHFSgcYB5PCp77Ir4fKPLQmHkMpAN65DokctO08d41E8a1Uk=", StringEncoding.BASE64),
                BlindA = Bytes.FromString("QAucC4Dzg9/qcJsDoDopkRXsja1uAsOCQw0qKuEaEn8=", StringEncoding.BASE64),
                BlindB = Bytes.FromString("Ub1/iklGLDXe+DwoviQ3tSiWd9hWTUpBJfWKhl9CSok=", StringEncoding.BASE64)
            };

            var isValid = phe.ValidateProofOfFail(proof, pkS, nS, c0, c1);

            Assert.True(isValid);
        }

        [Fact]
        public void Should_DecryptM_When_SpecifiedListOfParametersArePassed()
        {
            var phe = new PheCrypto();

            var pwd = Bytes.FromString("passw0rd");
            var skC = phe.DecodeSecretKey(Bytes.FromString("Ty+3kM7kPFQjZu1NKyJjHqdUnDl9/n7mlHu7VJMyLRw=", StringEncoding.BASE64));
            var nC  = Bytes.FromString("9Gr0Jrg+vux+xBOLpGLXemB7uuwq7xkIa4JVgAJG5Yw=", StringEncoding.BASE64);
            var c1  = Bytes.FromString("BMkSH2xpOLox46HQf0oq8vqtYApMezo7K83xCMDgsUzgpI75esc6KJTRrqf7Nq5+y2LiGwyfJ/X8wZ7IXywy+gg=", StringEncoding.BASE64);
            var t1  = Bytes.FromString("BPGSx7b84QaTFJoXJcQ70qPuppbGkh8udqSIZJ7R8AE6Br0CBvPw69exsa3jxeHmMN17vY9l9wXdZcQt7FST2fc=", StringEncoding.BASE64);
            var m   = Bytes.FromString("XslZXIrsVj1XYVF74gWfi0Lo4frLsDObirNl5mFwYeA=", StringEncoding.BASE64);

            var mm  = phe.DecryptM(skC, pwd, nC, t1, c1);

            Assert.Equal(m, mm);
        }
    }
}
