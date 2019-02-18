# Passw0rd .NET/C# SDK

[![Nuget package](https://img.shields.io/nuget/v/passw0rd.svg)](https://www.nuget.org/packages/Passw0rd/) 
[![Build status](https://ci.appveyor.com/api/projects/status/kqs4lqw426gbpccm/branch/release?svg=true)](https://ci.appveyor.com/project/unlim-it/sdk-net/branch/release)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<a href="https://passw0rd.io/"><img width="260px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/passw0rd.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) that provides developers with a technology to protect users passwords from offline/online attacks and make stolen passwords useless even if your database has been compromised.

PHE is a new, more secure mechanism that protects user passwords and lessens the security risks associated with weak passwords. Neither Virgil nor attackers know anything about user's password.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of user password
- Protection from online attacks
- Protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key


## Register Your Account
Before starting practicing with the SDK and usage examples be sure that:
- you have a registered passw0rd Account
- you created passw0rd Application
- and you got your passw0rd application's credentials, such as: Application Access Token, Service Public Key, Client Secret Key

If you don't have an account or a passw0rd project with its credentials, please use the [passw0rd CLI](https://github.com/passw0rd/cli) to get it.


## Install and Configure SDK
The Passw0rd .NET SDK is provided as a package named `Passw0rd`. The package is distributed via [NuGet package](https://docs.microsoft.com/en-us/nuget/quickstart/use-a-package) management system.

The package is available for .NET Core 2.1

**Supported platforms**:
- MacOS
- Linux
- Windows

### Install SDK Package

Installing the package using Package Manager Console:

```bash
PM> Install-Package Passw0rd -Version 0.2.0
```

### Configure SDK
Here is an example of how to specify your credentials SDK class instance:
```cs
using Passw0rd;

// here set your passw0rd credentials
var context = ProtocolContext.Create(
    appToken: "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
    servicePublicKey: "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    appSecretKey: "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc="
);

var protocol = new Protocol(context);
```



## Prepare Your Database
Passw0rd SDK allows you to easily perform all the necessary operations to create, verify and rotate user's `record`.

**Passw0rd record** - a user's password that is protected with our Passw0rd technology. Passw0rd `record` contains a version, client & server random salts and two values obtained during execution of the PHE protocol.

In order to create and work with user's `record` you have to set up your database with an additional column.

The column must have the following parameters:
<table class="params">
<thead>
        <tr>
            <th>Parameters</th>
            <th>Type</th>
            <th>Size (bytes)</th>
            <th>Description</th>
        </tr>
</thead>

<tbody>
<tr>
    <td>passw0rd_record</td>
    <td>bytearray</td>
    <td>210</td>
    <td> A unique record, namely a user's protected passw0rd.</td>
</tr>

</tbody>
</table>


## Usage Examples

### Enroll User Record

Use this flow to create a new passw0rd's `record` in your DB for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in into your system to implement Passw0rd technology. You can go through your database and enroll (create) a user's `record` at any time.

So, in order to create a `record` for a new database or available one, go through the following operations:
- Take a user's **password** (or its hash or whatever you use) and pass it into the `EnrollAccount` function in a SDK on your Server side.
- Passw0rd SDK will send a request to Passw0rd Service to get enrollment.
- Then, Passw0rd SDK will create a user's `record`. You need to store this unique user's `record` in your database in associated column.

```cs
using Passw0rd;
using Passw0rd.Phe;
using Passw0rd.Utils;

var password = "passw0rd";

// create a new encrypted password record using user password or its hash
var enrollResult = await protocol.EnrollAccountAsync(password);
// note that record is a byte array.

// save encrypted passw0rd record into your users DB
// you can save encrypted passw0rd record to database as byte array or as base64 string

// encode encrypted password record base64 string
var recordBase64 = Bytes.ToString(enrollResult.Record, StringEncoding.BASE64); 

//use encryptionKey for protecting user data
var phe = new PheCrypto();
var encrypted = phe.Encrypt(data, enrollResult.Key);
```

When you've created a passw0rd's `record` for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User Record

Use this flow when a user already has his or her own passw0rd's `record` in your database. This function allows you to verify user's password with the `record` from your DB every time when the user signs in. You have to pass his or her `record` from your DB into the `VerifyPasswordAsync` function:

```cs
using Passw0rd;
using Passw0rd.Phe;

// get user's encrypted password record from your users DB
var passwordCandidate = "passw0rd";

// check candidate password with encrypted password record from your DB
var verificationResult = await protocol.VerifyPasswordAsync(passwordCandidate, record);
// (VerificationResult.IsSuccess == false) if passwordCandidate is wrong.

//use verificationResult.Key for decrypting user data
var phe = new PheCrypto();
var decrypted = phe.Decrypt(encrypted, verificationResult.Key);
```

## Encrypt user data in your database

Not only user's password is a sensitive data. In this flow we will help you to protect any Personally identifiable information (PII) in your database.

PII is a data that could potentially identify a specific individual, and PII can be sensitive.
Sensitive PII is information which, when disclosed, could result in harm to the individual whose privacy has been breached. Sensitive PII should therefore be encrypted in transit and when data is at rest. Such information includes biometric information, medical information, personally identifiable financial information (PIFI) and unique identifiers such as passport or Social Security numbers.

Passw0rd service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from `EnrollAccount` or `VerifyPasswordAsync` functions. The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) the user's `record`. The `encryptionKey` will be updated after user changes own password.

Here is an example of data encryption/decryption with an `encryptionKey`:


```cs
using Passw0rd;
using Passw0rd.Phe;
using Passw0rd.Utils;

var phe = new PheCrypto();
var data = Bytes.FromString("Personal data", StringEncoding.UTF8);

//encryptionKey is obtained from protocol.EnrollAccountAsync()
// or protocol.VerifyPasswordAsync() calls
var ciphertext = phe.Encrypt(data, encryptionKey);
            
var decrypted = phe.Decrypt(ciphertext, encryptionKey);

//use decrypted data

```

Encryption is performed using AES256-GCM with key & nonce derived from the user's encryptionKey using HKDF and random 256-bit salt.

Virgil Security has Zero knowledge about a user's `encryptionKey`, because the key is calculated every time when you execute `EnrollAccount` or `VerifyPassword` functions at your server side.


## Rotate app keys and user record
There can never be enough security, so you should rotate your sensitive data regularly (about once a week). Use this flow to get an `UPDATE_TOKEN` for updating user's passw0rd `RECORD` in your database and to get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application.

Also, use this flow in case your database has been COMPROMISED!

> This action doesn't require to create an additional table or to do any modification with available one. When a user needs to change his or her own password, use the EnrollAccount function to replace user's oldPassw0rd record value in your DB with a newRecord.

There is how it works:

**Step 1.** Get your `UPDATE_TOKEN` using [Passw0rd CLI](https://github.com/passw0rd/cli)

- be sure you're logged in your account. To log in the account use the following command (2FA is required):

```bash
// FreeBSD / Linux / Mac OS
./passw0rd login my@email.com

// Windows OS
passw0rd login my@email.com
```

- then, use the `rotate` command and your application token to get an `UPDATE_TOKEN`:

```bash
// FreeBSD / Linux / Mac OS
./passw0rd application rotate <app_token>

// Windows OS
passw0rd application rotate <app_token>
```
as a result, you get your `UPDATE_TOKEN`.

**Step 2.** Initialize passw0rd SDK with the `UPDATE_TOKEN`.
Move to passw0rd SDK configuration file and specify your `UPDATE_TOKEN`:


```cs
using Passw0rd;

// here set your passw0rd credentials
var context = ProtocolContext.Create(
    appToken: "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
    servicePublicKey: "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    appSecretKey: "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc=",
    updateToken: "UT.2.00000000+0000000000000000000008UfxXDUU2FGkMvKhIgqjxA+hsAtf17K5j11Cnf07jB6uVEvxMJT0lMGv00000="
);

var protocol = new Protocol(context);
```

**Step 3.** Start migration. Use the `new RecordUpdater("UPDATE_TOKEN")` SDK function to create an instance of class that will update your old records to new ones (you don't need to ask your users to create a new password). The `Update()` function requires user's `oldRecord` from your DB:


```cs
using Passw0rd;
using Passw0rd.Utils;

var updater = new RecordUpdater("UPDATE_TOKEN");

//for each record get old record from the database as a byte array
//if you keep old record as a base64 string, get byte array from it:
var oldRecord = Bytes.FromString(oldRecordBase64, StringEncoding.BASE64)

//update old record
var newRecord = updater.Update(oldRecord);
//a WrongVersionException will be raised if "UPDATE_TOKEN" has wrong version.

//save new record to the database
saveNewRecord(newRecord);
```

So, run the `Update()` function and save user's `newRecord` into your database.

Since the SDK is able to work simultaneously with two versions of user's records (`newRecordBytes` and `oldRecordBytes`), this will not affect the backend or users. This means, if a user logs into your system when you do the migration, the passw0rd SDK will verify his password without any problems because Passw0rd Service can work with both user's records (`newRecordBytes` and `oldRecordBytes`).

**Step 4.** Get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application

Use passw0rd CLI `update-keys` command and your `UPDATE_TOKEN` to update the `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY`:

```bash
// FreeBSD / Linux / Mac OS
./passw0rd application update-keys <service_public_key> <app_secret_key> <update_token>

// Windows OS
passw0rd application update-keys <service_public_key> <app_secret_key> <update_token>
```

**Step 5.** Move to passw0rd SDK configuration and replace your previous `APP_SECRET_KEY`,  `SERVICE_PUBLIC_KEY` with a new one (`APP_TOKEN` will be the same). Delete previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` and `UPDATE_TOKEN`.


```cs
using Passw0rd;

// here set your passw0rd credentials
var context = ProtocolContext.Create(
    appToken: "APP_TOKEN_HERE",
    servicePublicKey: "NEW_SERVICE_PUBLIC_KEY_HERE",
    appSecretKey: "NEW_APP_SECRET_KEY_HERE",
);

var protocol = new Protocol(context);
```

## Docs
* [Passw0rd][_passw0rd] home page
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

Also, get extra help from our support team: support@VirgilSecurity.com.

[_passw0rd]: https://passw0rd.io/