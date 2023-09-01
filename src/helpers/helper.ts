// import { Request } from "express";
// import nodemailer from "nodemailer";
// import Axios from "axios";
// import ejs from "ejs";
// import jwt from "jsonwebtoken";
// import path from "path";
// import Mailjet from "node-mailjet";
// import Crypto from "crypto";

// // @ts-ignore
// import ActionClientPromptModel from "../models/ActionClientPromptModel";
// import CommonModel from "../models/CommonModel";
// import {
//   ActiveNotificationService,
//   NotificationMappingData,
//   NotificationServiceDetails,
//   EmailTransportConfigaration,
//   EmailAddressData,
//   Configuration,
//   EmailBodyDetails,
// } from "../types/notification-services";

// /* load models */
// export default {
//   generateOtp,
//   sendSMS,
//   sendOtpToEmail,
//   sendVerificationEmail,
//   regexEmail,
//   regexDob,
//   regexMobile,
//   regexPassword,
//   listFunction,
//   getActionByClientPromptActionId,
//   getActiveEmailProvider,
//   sendNotificationWithActionAndConfig,
//   encryptionByCrypto,
//   decryptBycrypto,
// };

// export async function generateOtp() {
//   return Math.floor(1000 + Math.random() * 9000);
// }

// export async function sendSMS(mobile: any, message: any) {}

// export async function sendOtpToEmail(
//   email: string,
//   otp: number,
//   firstName: string
// ) {
//   // need to pass the email
//   const notificationData: ActiveNotificationService | null =
//     await getActiveEmailProvider();
//   if (!notificationData) {
//     throw "No active email found";
//   }

//   const configuration = {
//     email: [email],
//     from: notificationData.configuration?.from,
//     publicKey: notificationData.configuration?.publicKey,
//     privateKey: notificationData.configuration?.privateKey,
//     subject: "Verify your email!",
//     fileName: "otp_email.ejs",
//     firstNameR: firstName,
//     otp,
//   };

//   sendMailByMailjet(configuration);
// }

// export async function sendVerificationEmail(
//   email: string,
//   link: string,
//   firstName: string
// ) {
//   // need to pass the email
//   const notificationData: ActiveNotificationService | null =
//     await getActiveEmailProvider();
//   if (!notificationData) {
//     throw "No active email found";
//   }

//   const configuration = {
//     email: [email],
//     from: notificationData.configuration?.from,
//     publicKey: notificationData.configuration?.publicKey,
//     privateKey: notificationData.configuration?.privateKey,
//     subject: "Verify your email",
//     fileName: "verification.ejs",
//     firstNameR: firstName,
//     link,
//   };

//   sendMailByMailjet(configuration);
// }

// export async function regexEmail(email: string) {
//   const emailRegex = new RegExp(
//     /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/
//   );
//   const isValidEmail: boolean = emailRegex.test(email);
//   return isValidEmail;
// }

// export async function regexMobile(mobile: string) {
//   const phoneRegex = new RegExp(/^[6789]\d{9}$/);
//   const isValidPhone: boolean = phoneRegex.test(mobile);
//   return isValidPhone;
// }

// export async function regexDob(dob: string) {
//   const dobRegex = new RegExp(/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/);
//   const isValidDob: boolean = dobRegex.test(dob);
//   return isValidDob;
// }

// export async function regexPassword(password: string) {
//   const clientSecretRegex = new RegExp(/[A-Za-z0-9]{8}/);
//   const isValidPassword: boolean = clientSecretRegex.test(password);
//   return isValidPassword;
// }

// export async function listFunction(inputData: any) {
//   inputData.filter =
//     [undefined, null].indexOf(inputData.filter) < 0
//       ? typeof inputData.filter === "string"
//         ? JSON.parse(inputData.filter)
//         : inputData.filter
//       : null;
//   inputData.range =
//     [undefined, null].indexOf(inputData.range) < 0
//       ? typeof inputData.range === "string"
//         ? JSON.parse(inputData.range)
//         : inputData.range
//       : null;
//   inputData.sort =
//     [undefined, null].indexOf(inputData.sort) < 0
//       ? typeof inputData.sort === "string"
//         ? JSON.parse(inputData.sort)
//         : inputData.sort
//       : null;

//   return {
//     filter: inputData.filter ?? null,
//     range: inputData.range ?? null,
//     sort: inputData.sort ?? null,
//   };
// }

// // get action by clientPromptId
// export async function getActionByClientPromptActionId(
//   clientPromptActionId: number
// ) {
//   const actionClientPromptData: NotificationMappingData[] =
//     await ActionClientPromptModel.getClientActionPromptDetail(
//       "actionClientPromptMapping",
//       clientPromptActionId
//     );
//   return actionClientPromptData;
// }

// // get active email provider with config
// export async function getActiveEmailProvider() {
//   const model = new CommonModel(
//     "notificationServices",
//     "notificationServiceId",
//     []
//   );

//   const activeMailService: NotificationServiceDetails[] = await model.list({
//     isActive: true,
//   });
//   if (!activeMailService?.length) {
//     return null;
//   }
//   const detailData: ActiveNotificationService = {
//     service: activeMailService[0]?.service,
//     serviceType: activeMailService[0]?.serviceType,
//     configuration: activeMailService[0]?.configuration,
//     host: activeMailService[0]?.host,
//     port: activeMailService[0]?.port,
//     encryption: activeMailService[0]?.encryption,
//   };
//   return activeMailService?.length ? detailData : null;
// }

// // call helper by actionName and configuration
// export async function sendNotificationWithActionAndConfig(
//   action: string,
//   configuration: any
// ) {
//   const emailProviderByService: ActiveNotificationService | null =
//     await getActiveEmailProvider();
//   if (!emailProviderByService) {
//     throw "No active notification service found";
//   }
//   try {
//     if (action === "web-hook") {
//       await sendByWebhook(configuration);
//     } else if (action === "send-email") {
//       if (emailProviderByService.service === "google") {
//         // for gmail
//         await sendEmailToEmail(configuration);
//       } else if (emailProviderByService.service.toLowerCase() === "mailjet") {
//         // for mailjet
//         await sendMailByMailjet(configuration);
//       }
//     }
//   } catch (error) {
//     throw error;
//   }
// }

// export async function sendMailByMailjet(configuration: Configuration) {
//   try {
//     return new Promise(async (resolve, reject) => {
//       if (!configuration.fileName) {
//         configuration.fileName = "default.ejs";
//       }

//       const mailjet = Mailjet.apiConnect(
//         configuration.publicKey as string,
//         configuration.privateKey as string
//       );
//       const emailArr: EmailAddressData[] = [];
//       if (Array.isArray(configuration.email)) {
//         configuration.email.forEach((email) => {
//           emailArr.push({
//             Email: email,
//           });
//         });
//       } else if (configuration.email) {
//         emailArr.push({
//           Email: configuration.email,
//         });
//       }

//       // for Cc mails
//       const ccEmailArr: EmailAddressData[] = [];
//       if (Array.isArray(configuration?.cc)) {
//         configuration.cc.forEach((email) => {
//           ccEmailArr.push({
//             Email: email,
//           });
//         });
//       } else if (configuration.cc) {
//         ccEmailArr.push({
//           Email: configuration.cc,
//         });
//       }

//       // for Bcc mails
//       const bccEmailArr: EmailAddressData[] = [];

//       if (Array.isArray(configuration?.bcc)) {
//         configuration.bcc.forEach((email) => {
//           bccEmailArr.push({
//             Email: email,
//           });
//         });
//       } else if (configuration.bcc) {
//         bccEmailArr.push({
//           Email: configuration.bcc,
//         });
//       }

//       ejs.renderFile(
//         path.join(__dirname, `../views/email/en/${configuration.fileName}`),
//         configuration,
//         (err, result) => {
//           if (err) {
//             throw err;
//           }

//           mailjet
//             .post("send", { version: "v3.1" })
//             .request({
//               Messages: [
//                 {
//                   From: {
//                     Email: configuration.from,
//                   },
//                   To: emailArr,
//                   Subject: configuration.subject,
//                   TextPart: configuration.body,
//                   HTMLPart: result,
//                 },
//               ],
//             })
//             .then((result) => {
//               return resolve(result.body);
//             })
//             .catch((err) => {
//               return reject(err.response.data);
//             });
//         }
//       );
//     });
//   } catch (error) {
//     throw error;
//   }
// }

// export async function sendEmailToEmail(configuration: Configuration) {
//   try {
//     const emailProviderByService: ActiveNotificationService | null =
//       await getActiveEmailProvider();
//     if (!emailProviderByService) {
//       throw "No active notification service found";
//     }
//     if (!configuration.fileName) {
//       configuration.fileName = "default.ejs";
//     }

//     // node mailer config
//     const config: EmailTransportConfigaration = {
//       host: emailProviderByService.host as string,
//       port: parseInt(emailProviderByService.port as string),
//       auth: {
//         user: emailProviderByService.configuration?.publicKey as string,
//         pass: emailProviderByService.configuration?.privateKey as string,
//       },
//     };
//     const transport = nodemailer.createTransport(config);

//     const emailArr: EmailAddressData[] = [];
//     const ccEmailArr: string[] = [];
//     const bccEmailArr: string[] = [];

//     if (Array.isArray(configuration.email)) {
//       configuration.email.forEach((email) => {
//         emailArr.push({
//           Email: email,
//         });
//       });
//     } else if (configuration.email) {
//       emailArr.push({
//         Email: configuration.email,
//       });
//     }

//     if (Array.isArray(configuration?.cc)) {
//       configuration.cc.forEach((email) => {
//         ccEmailArr.push(email);
//       });
//     } else if (configuration.cc) {
//       ccEmailArr.push(configuration.cc);
//     }

//     if (Array.isArray(configuration.bcc)) {
//       configuration.bcc?.forEach((email) => {
//         bccEmailArr.push(email);
//       });
//     } else if (configuration.bcc) {
//       bccEmailArr.push(configuration.bcc);
//     }

//     console.log(`emailArr`, emailArr);
//     return new Promise((resolve, reject) => {
//       ejs.renderFile(
//         path.join(__dirname, `../views/email/en/${configuration.fileName}`),
//         configuration,
//         (err, result) => {
//           emailArr.forEach((_email) => {
//             console.log(`_email`, _email);
//             if (err) {
//               console.log(`err?.message`, err?.message);
//               throw err;
//             } else {
//               const message: EmailBodyDetails = {
//                 from: configuration.from as string,
//                 to: _email.Email,
//                 cc: ccEmailArr,
//                 bcc: bccEmailArr,
//                 subject: configuration.subject as string,
//                 html: result,
//                 attachments: configuration.attachments,
//               };
//               transport.sendMail(message, function (err1, info) {
//                 if (err1) {
//                   console.log(`err1?.message`, err1?.message);
//                   return reject(err1);
//                 } else {
//                   return resolve(info);
//                 }
//               });
//             }
//           });
//         }
//       );
//     });
//   } catch (error: any) {
//     console.log(`error?.message`, error?.message);
//     throw error;
//   }
// }

// // call helper function according to action & config
// export async function sendByWebhook(data: any) {
//   if (!data.config) {
//     throw "Configuration is missing";
//   }

//   const config = data.config;
//   try {
//     await Axios({
//       method: config.method?.toString().toLowerCase(),
//       url: config.apiUrl as string,
//       data: config.body,
//     });
//   } catch (error) {
//     throw "unexpected error";
//   }
// }

// // get data from configuration
// const encryptCred: {
//   secret_key: string;
//   secret_iv: string;
//   encryption_method: string;
// } = {
//   secret_key: process.env.CRYPTO_SECRET_KEY as string,
//   secret_iv: process.env.CRYPTO_SECRET_IV as string,
//   encryption_method: process.env.CRYPTO_ENCRYPTION_METHOD as string,
// };

// // Generate secret hash with crypto to use for encryption
// const key = Crypto.createHash("sha256")
//   .update(encryptCred.secret_key)
//   .digest("hex")
//   .substring(0, 32);
// const encryptionIV = Crypto.createHash("sha256")
//   .update(encryptCred.secret_iv)
//   .digest("hex")
//   .substring(0, 16);

// // encrypt by crypto aes 256
// export async function encryptionByCrypto(data: any) {
//   console.log(data);
//   data = typeof data === "object" ? JSON.stringify(data) : data;
//   if (
//     !encryptCred.secret_key ||
//     !encryptCred.secret_iv ||
//     !encryptCred.encryption_method
//   ) {
//     throw new Error("secretKey, secretIV, and ecnryptionMethod are required");
//   }

//   // Encrypt data
//   const cipher = Crypto.createCipheriv(
//     encryptCred.encryption_method,
//     key,
//     encryptionIV
//   );
//   return Buffer.from(
//     cipher.update(data, "utf8", "hex") + cipher.final("hex")
//   ).toString("base64");
// }

// // decrypt by crypto aes 256
// export async function decryptBycrypto(encryptedData: string) {
//   const buff = Buffer.from(encryptedData, "base64");
//   const decipher = Crypto.createDecipheriv(
//     encryptCred.encryption_method,
//     key,
//     encryptionIV
//   );
//   return JSON.parse(
//     decipher.update(buff.toString("utf8"), "hex", "utf8") +
//       decipher.final("utf8")
//   );
// }
