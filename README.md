# Virgil PureKit .NET/C# SDK

[![Nuget package](https://img.shields.io/nuget/v/virgil.purekit.svg)](https://www.nuget.org/packages/Virgil.PureKit/) 
[![Build status](https://ci.appveyor.com/api/projects/status/i2ef7y13y798wawr?svg=true)(https://ci.appveyor.com/project/unlim-it/sdk-net)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)


## Introduction
<img src="https://cdn.virgilsecurity.com/assets/images/github/logos/pure_grey_logo.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a powerful and revolutionary cryptographic technology that provides stronger and more modern security, that secures users' data and lessens the security risks associated with weak passwords.

Virgil PureKit allows developers interacts with Virgil PHE Service to protect users' passwords and sensitive personal identifiable information (PII data) in a database from offline/online attacks and makes stolen passwords/data useless if your database has been compromised. Neither Virgil nor attackers know anything about users' passwords/data.

This technology can be used within any database or login system that uses a password, so it’s accessible for a company of any industry or size.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of users' passwords
- Passwords & data protection from online attacks
- Passwords & data protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key


## Register Your Account
Before starting practicing with the SDK and usage examples make sure that:
- you have a registered Virgil Account at [Virgil Dashboard](https://dashboard.virgilsecurity.com/)
- you created PURE Application
- and you got your PureKit application's credentials such as: `APP_TOKEN`, `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY`


## Install and Configure PureKit
The Virgil.PureKit .NET/C# SDK is provided as a package named `Virgil.PureKit`. The package is distributed via [NuGet package](https://docs.microsoft.com/en-us/nuget/quickstart/use-a-package) management system.

The package is available for .NET Core 2.1

**Supported platforms**:
- MacOS
- Linux
- Windows

### Install PureKit Package

Installing the package using Package Manager Console:

```bash
PM> Install-Package Virgil.PureKit -Version 2.0.0
```

### Configure PureKit
Here is an example of how to specify your credentials Protocol class instance:
```cs
using Virgil.PureKit;

// here set your PURE App credentials
var context = ProtocolContext.Create(
    appToken: "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
    servicePublicKey: "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    appSecretKey: "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc="
);

var protocol = new Protocol(context);
```

## Prepare Your Database
Virgil.PureKit SDK allows you to easily perform all the necessary operations to create, verify and rotate (update) user's `PureRecord`.

**Pure Record** - a user's password that is protected with our PureKit technology. Pure `record` contains a version, client & server random salts and two values obtained during execution of the PHE protocol.

In order to create and work with user's Pure `record` you have to set up your database with an additional column.

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
    <td>record</td>
    <td>bytearray</td>
    <td>210</td>
    <td> A unique record, namely a user's protected Pure Record.</td>
</tr>

</tbody>
</table>


## Usage Examples

### Enroll User Record

Use this flow to create a `PureRecord` in your DB for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in into your
 system to implement PHE technology. You can go through your database and enroll (create) a user's
 Pure `Record` at any time.

So, in order to create a Pure `Record` for a new database or available one, go through the following operations:
- Take a user's **password** (or its hash or whatever you use) and pass it into the `EnrollAccountAsync` function in a PureKit on your Server side.
- PureKit will send a request to PureKit service to get enrollment.
- Then, PureKit will create a user's Pure `Record`. You need to store this unique user's Pure `Record` in your database in associated column.

```cs
using Virgil.PureKit;
using Virgil.PureKit.Phe;
using Virgil.PureKit.Utils;

var password = "passw0rd";

// create a new encrypted Pure record using user password or its hash
var enrollResult = await protocol.EnrollAccountAsync(password);
// note that enrollResult.Record is a byte array.

// save encrypted Pure record into your users DB
// you can save encrypted Pure record enrollResult.Record to database as byte array or as base64 string

// encode encrypted password record base64 string
var recordBase64 = Bytes.ToString(enrollResult.Record, StringEncoding.BASE64); 

//use encryption key enrollResult.Key for protecting user data
var phe = new PheCrypto();
var encrypted = phe.Encrypt(data, enrollResult.Key);
```

When you've created a Pure `record` for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User Record

Use this flow when a user already has his or her own Pure `record` in your database. This function allows you to
verify user's password with the Pure `record` from your DB every time when the user signs in. You have to pass his or her Pure `record` from your DB into the `VerifyPasswordAsync` function:

```cs
using Virgil.PureKit;
using Virgil.PureKit.Phe;

// get user's encrypted Pure record from your users DB
var passwordCandidate = "passw0rd";

// check candidate password with encrypted Pure record from your DB
var verifyResult = await protocol.VerifyPasswordAsync(passwordCandidate, record);
// (verifyResult.IsSuccess == false) if passwordCandidate is wrong.

//use verifyResult.Key for decrypting user data
var phe = new PheCrypto();
var decrypted = phe.Decrypt(encrypted, verifyResult.Key);
```

## Encrypt user data in your database

Not only user's password is a sensitive data. In this flow we will help you to protect any Personally identifiable information (PII) in your database.

PII is a data that could potentially identify a specific individual, and PII can be sensitive.
Sensitive PII is information which, when disclosed, could result in harm to the individual whose privacy has been breached. Sensitive PII should therefore be encrypted in transit and when data is at rest. Such information includes biometric information, medical information, personally identifiable financial information (PIFI) and unique identifiers such as passport or Social Security numbers.

PureKit service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from
`EnrollAccount` or `VerifyPassword` functions. The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) the user's
`PureRecord`. The `encryptionKey` will be updated after user changes own password.

Here is an example of data encryption/decryption with an `encryptionKey`:


```cs
using Virgil.PureKit;
using Virgil.PureKit.Phe;
using Virgil.PureKit.Utils;

var phe = new PheCrypto();
var data = Bytes.FromString("Personal data", StringEncoding.UTF8);

//verifyResult.Key is obtained from protocol.EnrollAccountAsync()
// or protocol.VerifyPasswordAsync() calls
var ciphertext = phe.Encrypt(data, verifyResult.Key);
            
var decrypted = phe.Decrypt(ciphertext, verifyResult.Key);

//use decrypted data

```

Encryption is performed using AES256-GCM with key & nonce derived from the user's encryptionKey using HKDF and random 256-bit salt.

Virgil Security has Zero knowledge about a user's `encryptionKey`, because the key is calculated every time when you execute `EnrollAccountAsync` or `VerifyPasswordAsync` functions at your server side.

## Rotate app keys and user PureRecord
There can never be enough security, so you should rotate your sensitive data regularly (about once a week). Use this
flow to get an `UPDATE_TOKEN` for updating user's `PureRecord` in your database and to get a new `APP_SECRET_KEY`
and `SERVICE_PUBLIC_KEY` of a specific application.

Also, use this flow in case your database has been COMPROMISED!

> This action doesn't require to create an additional table or to modify scheme of existing table. When a user needs to change his or her own password, use the EnrollAccount function to replace user's oldRecord in your DB with a newRecord.

There is how it works:

**Step 1.** Get your `UPDATE_TOKEN`

Navigate to [Virgil Dashboard](https://dashboard.virgilsecurity.com/login), open your pure application panel and press "Show update token" button to get the `UPDATE_TOKEN`.

**Step 2.** Initialize PureKit with the `UPDATE_TOKEN`
Move to Virgil.PureKit SDK configuration file and specify your `UPDATE_TOKEN`:


```cs
using Virgil.PureKit;

// here set your PURE App credentials
var context = ProtocolContext.Create(
    appToken: "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
    servicePublicKey: "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    appSecretKey: "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc=",
    updateToken: "UT.2.00000000+0000000000000000000008UfxXDUU2FGkMvKhIgqjxA+hsAtf17K5j11Cnf07jB6uVEvxMJT0lMGv00000="
);

var protocol = new Protocol(context);
```

**Step 3.** Start migration. Use the `new RecordUpdater("UPDATE_TOKEN")` SDK function to create an instance of class that will update your old records to new ones (you don't need to ask your users to create a new password). The `Update()` function requires user's old Pure `record` from your DB:


```cs
using Virgil.PureKit;
using Virgil.PureKit.Utils;

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

So, run the `Update()` function and save user's new Pure `record` into your database.

Since the PureKit is able to work simultaneously with two versions of user's PureRecords (new Pure `record` and old Pure `record`),
 this will not affect the backend or users. This means, if a user logs into your system when you do the migration,
 the Virgil PureKit will verify his password without any problems because PureKit can work with both user's Pure Records (new and old).


**Step 4.** Get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application

Use Virgil CLI `update-keys` command and your `UPDATE_TOKEN` to update the `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY`:

```bash
// FreeBSD / Linux / Mac OS
./virgil pure update-keys <service_public_key> <app_secret_key> <update_token>

// Windows OS
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

**Step 5.** Move to Virgil.PureKit SDK configuration file and replace your previous `APP_SECRET_KEY`,  `SERVICE_PUBLIC_KEY` with a new one (`APP_TOKEN` will be the same). Delete previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` and `UPDATE_TOKEN`.


```cs
using Virgil.PureKit;

// here set your PURE App credentials
var context = ProtocolContext.Create(
    appToken: "APP_TOKEN_HERE",
    servicePublicKey: "NEW_SERVICE_PUBLIC_KEY_HERE",
    appSecretKey: "NEW_APP_SECRET_KEY_HERE",
);

var protocol = new Protocol(context);
```

## Docs
* [Virgil Dashboard](https://dashboard.virgilsecurity.com)
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
