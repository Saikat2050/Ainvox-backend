import {Request} from "express"
import nodemailer from "nodemailer"
import Axios from "axios"
import ejs from "ejs"
import jwt from "jsonwebtoken"
import path from "path"
import Crypto from "crypto"
import eventEmitter from "../lib/logging"

const transporter = nodemailer.createTransport({
	service: process.env.NODMAILER_SERVICE,
	host: process.env.NODMAILER_HOST,
	port: 587,
	secure: false,
	auth: {
		user: process.env.NODEMAILER_USER,
		pass: process.env.NODMAILER_PASSWORD
	}
})

/* load models */
export default {
	generateOtp,
	sendSMS,
	regexEmail,
	regexDob,
	regexMobile,
	regexPassword,
	listFunction,
	encryptionByCrypto,
	decryptBycrypto,
	sendOtpToEmail
}

export async function generateOtp() {
	return Math.floor(1000 + Math.random() * 9000)
}

export async function sendSMS(mobile: any, message: any) {}

export async function sendOtpToEmail(
	email: string,
	otp: number,
	firstName: string,
	fileName?: string
) {
	// need to pass the email
	const configuration: any = {
		subject: "Verify your email!",
		firstName,
		otp
	}

	try {
		if (!fileName) {
			fileName = "default.ejs"
		}

		return new Promise((resolve, reject) => {
			ejs.renderFile(
				path.join(__dirname, `../../views/email/${fileName}`),
				configuration,
				(err, result) => {
					if (err) {
						eventEmitter.emit(`err?.message`, err?.message)
						throw err
					} else {
						const message = {
							from: process.env.NODEMAILER_USER as string,
							to: email,
							subject: configuration.subject,
							html: result
						}
						transporter.sendMail(message, function (error, info) {
							if (error) {
								eventEmitter.emit(`logging`, error?.message)
								return reject(error)
							} else {
								return resolve(info)
							}
						})
					}
				}
			)
		})
	} catch (error: any) {
		eventEmitter.emit(`logging`, error?.message)
		throw error
	}
}

export async function regexEmail(email: string) {
	const emailRegex = new RegExp(
		/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/
	)
	const isValidEmail: boolean = emailRegex.test(email)
	return isValidEmail
}

export async function regexMobile(mobile: string) {
	const phoneRegex = new RegExp(/^[6789]\d{9}$/)
	const isValidPhone: boolean = phoneRegex.test(mobile)
	return isValidPhone
}

export async function regexDob(dob: string) {
	const dobRegex = new RegExp(/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/)
	const isValidDob: boolean = dobRegex.test(dob)
	return isValidDob
}

export async function regexPassword(password: string) {
	const clientSecretRegex = new RegExp(/[A-Za-z0-9]{8}/)
	const isValidPassword: boolean = clientSecretRegex.test(password)
	return isValidPassword
}

export async function listFunction(inputData: any) {
	inputData.filter =
		[undefined, null].indexOf(inputData.filter) < 0
			? typeof inputData.filter === "string"
				? JSON.parse(inputData.filter)
				: inputData.filter
			: null
	inputData.range =
		[undefined, null].indexOf(inputData.range) < 0
			? typeof inputData.range === "string"
				? JSON.parse(inputData.range)
				: inputData.range
			: null
	inputData.sort =
		[undefined, null].indexOf(inputData.sort) < 0
			? typeof inputData.sort === "string"
				? JSON.parse(inputData.sort)
				: inputData.sort
			: null

	return {
		filter: inputData.filter ?? null,
		range: inputData.range ?? null,
		sort: inputData.sort ?? null
	}
}

// get data from configuration
const encryptCred: {
	secret_key: string
	secret_iv: string
	encryption_method: string
} = {
	secret_key: process.env.CRYPTO_SECRET_KEY as string,
	secret_iv: process.env.CRYPTO_SECRET_IV as string,
	encryption_method: process.env.CRYPTO_ENCRYPTION_METHOD as string
}

// Generate secret hash with crypto to use for encryption
const key = Crypto.createHash("sha256")
	.update(encryptCred.secret_key)
	.digest("hex")
	.substring(0, 32)
const encryptionIV = Crypto.createHash("sha256")
	.update(encryptCred.secret_iv)
	.digest("hex")
	.substring(0, 16)

// encrypt by crypto aes 256
export async function encryptionByCrypto(data: any) {
	data = typeof data === "object" ? JSON.stringify(data) : data
	if (
		!encryptCred.secret_key ||
		!encryptCred.secret_iv ||
		!encryptCred.encryption_method
	) {
		throw new Error(
			"secretKey, secretIV, and ecnryptionMethod are required"
		)
	}

	// Encrypt data
	const cipher = Crypto.createCipheriv(
		encryptCred.encryption_method,
		key,
		encryptionIV
	)
	return Buffer.from(
		cipher.update(data, "utf8", "hex") + cipher.final("hex")
	).toString("base64")
}

// decrypt by crypto aes 256
export async function decryptBycrypto(encryptedData: string) {
	const buff = Buffer.from(encryptedData, "base64")
	const decipher = Crypto.createDecipheriv(
		encryptCred.encryption_method,
		key,
		encryptionIV
	)
	return JSON.parse(
		decipher.update(buff.toString("utf8"), "hex", "utf8") +
			decipher.final("utf8")
	)
}
