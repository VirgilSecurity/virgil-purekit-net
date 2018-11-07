# Passw0rd .NET/C# SDK

[![Nuget package](https://img.shields.io/nuget/v/passw0rd.svg)](https://www.nuget.org/packages/Passw0rd/) [![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Passw0rd Features](#passw0rd-features) | [Register your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Setup your Database](#setup-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<a href="https://passw0rd.io/"><img width="260px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/passw0rd.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces to developers an implementation of the [Password-Hardened Encryption (PHE) protocol](https://www.chaac.tf.fau.de/files/2018/06/main.pdf) that provides developers with a technology to protect users passwords from offline attacks and make stolen passwords useless even if your database is breached.

PHE is a new, more secure mechanism that protects user passwords and lessens the security risks associated with weak passwords. Neither Virgil nor attackers know anything about user's password.


## Passw0rd Features
- zero knowledge of user's password
- protection from online attacks
- protection from offline attacks
- instant invalidation of stolen database
- user data encryption with a personal key


## Register your Account
Before start practicing with the SDK and usage examples be sure that:
- you have a registered Account at Virgil Cloud
- you have a registered Passw0rd Application
- and you got your Passw0rd Application's credentials, such as: Application ID, Access Token, Service Public Key, Client Secret Key.

If you don't have an account or a passw0rd's project with its credentials, please use a [Passw0rd CLI](https://github.com/passw0rd/cli) to get it.


## Install and configure SDK
The Passw0rd .NET SDK is provided as a package named `Passw0rd`. The package is distributed via [NuGet package](https://docs.microsoft.com/en-us/nuget/quickstart/use-a-package) management system.

The package is available for .NET Framework 4.5 and newer.

**Supported platforms**:
- MacOS,
- Linux,
- Windows.

### Install SDK Package

Installing the package using Package Manager Console:

```bash
Run PM> Install-Package Passw0rd -Version 0.1.0
```


### Configure SDK
Here is an example of how to specify your credentials SDK class instance:
```cs
// specify your account and app's credentials
var context = ProtocolContext.Create(
    appId:           "58533793ee4f41bf9fcbf178dbac9b3a",
    accessToken:     "-KM2dB9-butQv1Op6l0L5TEFy2fL-zty",
    serverPublicKey: "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    clientSecretKey: "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc="
);

var protocol = new Protocol(context);
```

## Setup your Database
Passw0rd SDK lets you easily perform all the necessary operations to create, verify and update user's password without requiring any additional actions.

In order to create and work with user's protected passw0rd you have to set up your database with additional column.

The column must be with following parameters:
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

### Enroll a user's passw0rd

Use this flow to create a new passw0rd record in your DB for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in into your system to implement Passw0rd. You can go through your database and enroll a user's passw0rd at any time.

So, in order to create passw0rd for a new database or available one, go through the following operations:
- Take a user's **password** (or its hash or whatever you use) and pass it into a `EnrollAsync` function in SDK on your Server side.
- Passw0rd SDK will send a request to Passw0rd Service to get enrollment.
- Then, Passw0rd SDK will create a user's Passw0rd **record**. You need to store this unique user's `record` (recordBytes or recordBase64 format) in your database in associated column.

```cs
var password = "passw0rd";

// create a new encrypted password record using user's password or its hash
var record = await protocol.EnrollAsync(password);

// save encrypted password record into your users DB

var recordBytes = record.Encode();          // encode encrypted password record into bytearray
var recordBase64 = record.EncodeToBase64(); // encode encrypted password record base64 string

// save record into your users DB
```

If you create a `passw0rd_record` for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify user's passw0rd

Use this flow when a user already has his or her own `record` in your database. This function lets you verify user's password with encrypted `record` from your DB user's password every time when user sign in. You have to pass his or her `record` from your DB into an `VerifyAsync` function:

```cs
// get user's encrypted password record from your users DB
var passwordCandidate = "passw0rd";

// check candidate password with encrypted password record from your DB
var isValid = await protocol.VerifyAsync(passwordCandidate, record);

if (!isValid)
{
    throw new Exception("Authentication failed");
}
```


### Update user's passw0rd

This function allows you to use a special `UpdateTokens` to update users' `record` in your database.

> Use this flow only if your database was COMPROMISED!
When user just needs to change own password use enroll function to replace old user's password_record value in your DB with a new user's password_record.

How it works:
- Get your `UpdateToken` using [Passw0rd CLI](https://github.com/passw0rd/cli).
- Specify the `UpdateToken` in the Passw0rd SDK on your Server side.
- Then you use `Update` records function to create new user's `record` for your users (you don't need to ask your users to create a their password).
- Finally, save a new user's `record` into your database.

Here is an example of using the `Update` records function:
```cs
// set up an UpdateToken that you got from passw0rd CLI in config
var context = ProtocolContext.Create(
    appId:           "58533793ee4f41bf9fcbf178dbac9b3a",
    accessToken:     "-KM2dB9-butQv1Op6l0L5TEFy2fL-zty",
    serverPublicKey: "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    clientSecretKey: "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc=",
    updateTokens:    new {
        "UT.2.MEQEIF9FaIoBlwvyV1HuIYw1cEL0GF6TyjJqYpO/b/uzsg88BCB0Cx2dnG8QKFyHr/nTOjQr7qeWgrM7T9CAg0D8p+EvVQ=="
    }
);

var protocol = new Protocol(context);

// get previous user's encrypted password record from a compromised DB
// update previous user's encrypted password record, and save new one into your DB
var newRecord = protocol.Update(record);
```


## Docs
* [Passw0rd][_passw0rd] home page
* [The PHE WhitePaper](https://eprint.iacr.org/2015/644.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

Also, get extra help from our support team: support@VirgilSecurity.com.

[_passw0rd]: https://passw0rd.io/
