import {Request, Response, NextFunction} from "express"
import moment from "moment"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import User from "../models/users"

import {
	SignInPayload,
	RegisterPayload,	
	SendOtpPayload,
	VerifyOtpPayload,
	ResetPasswordPayload,
	sendOtpPayload,
	verifyOtpPayload
} from "../types/auth"
import {UserCreateApiPayload, UserDetails, UserShortDetails} from "../types/users"
import helper, { decryptBycrypto, encryptionByCrypto} from "../helpers/helper"
import {ApiResponse} from "../helpers/ApiResponse"
import errorData from "../constants/errorData.json"

class AuthController {
	constructor() {
		this.register = this.register.bind(this)
		this.sendOtp = this.sendOtp.bind(this)
		this.verifyOtp = this.verifyOtp.bind(this)
		this.resetPassword = this.resetPassword.bind(this)
		this.signIn = this.signIn.bind(this)
		this.refreshToken = this.refreshToken.bind(this)
	}

	public async register(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			const inputData: RegisterPayload = req.body

			const [isValidEmail, isValidPhone, isValidPassword]: [
				boolean,
				boolean,
				boolean
			] = await Promise.all([
				// email validation
				helper.regexEmail(inputData.email),

				// phone validation
				inputData.mobile ? helper.regexMobile(inputData.mobile) : false,

				// password validation
				helper.regexPassword(inputData.password)
			])

			if (!isValidEmail) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "Email not valid"
				})
			}
			if (inputData.mobile && !isValidPhone) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "Phone number not valid"
				})
			}
			if (!isValidPassword) {
				return response.errorResponse({
					...errorData.BAD_REQUEST,
					message: "Password must be more then 8 char"
				})
			}

			const [phoneExists, userExists]: [boolean, boolean] = await Promise.all([
				inputData.mobile
					? User.findOne({ //i have checked with mongo find does exist if you don't 
							mobile: inputData.mobile,
							isDeleted: false
					  })
					: [],
					User.findOne({
					email: inputData.email,
					isDeleted: false
				})
			])
			if (phoneExists && phoneExists) {
				return response.errorResponse({
					...errorData.ALREADY_EXISTS,
					message: "Phone number already exists"
				})
			}
			if (userExists) {
				return response.errorResponse({
					...errorData.ALREADY_EXISTS,
					message: "User email already exists"
				})
			}

			// hashing password
			inputData.password = await bcrypt.hash(
				inputData.password,
				parseInt(process.env.SALT_ROUNDS as string)
			)

			const data: UserCreateApiPayload | null = await User.create(inputData)

			return response.successResponse({
				message: "User created successfully",
				data
			})
		} catch (error) {
			next(error)
		}
	}

	public async sendOtp(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			const {email}: SendOtpPayload = req.body
			//check if user exist
			const userExists: UserDetails | null = await User.findOne({
				email,
				isDeleted: false,
				isActive: true
			})
			if (!userExists) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "User not found"
				})
			}
			const otpRandom: number =  Math.floor(1000 + Math.random() * 9000)
			await User.updateOne({
				secrectCode: await decryptBycrypto(otpRandom.toString())
			})

			// // send otp to email
			// await sendOtpToEmail(
			// 	authCredential.userName,
			// 	otp,
			// 	userDetails.firstName
			// )

			return response.successResponse({
				message: `OTP sent successfully`
			})
		} catch (error) {
			next(error)
		}
	}

	public async verifyOtp(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			const {email, otp}: verifyOtpPayload = req.body
			
			// check if otp is valid
			const userExists: UserDetails | null = await User.findOne({
				email,
				secretCode: await encryptionByCrypto(otp),
				isDeleted: false,
				isActive: true
			})
			if (!userExists) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "User not found"
				})
			}
			
			return response.successResponse({
				message: `OTP verified successfully`
			})
		} catch (error) {
			next(error)
		}
	}

	public async resetPassword(
		req: Request,
		res: Response,
		next: NextFunction
	) {
		try {
			const response = new ApiResponse(res)
			const {email, otp, password}: ResetPasswordPayload = req.body
			// encrypt password
			const isValidPassword: boolean =
				await helper.regexPassword(password)
			if (!isValidPassword) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "Password must be more then 8 char"
				})
			}
			const encryptPassword: string = await bcrypt.hash(
				password,
				parseInt(process.env.SALT_ROUNDS as string)
			)

			const listUserData: UserShortDetails | null = await User.findOne({email})
			if (!listUserData) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "User not found"
				})
			}

			const hashPass: boolean = await bcrypt.compare(otp, encryptPassword)
			if (!hashPass) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "User not found"
				})
			}

			if (
				new Date(
					new Date(listUserData?.createdAt.toString()).getTime() +
						parseInt(
							process.env.OTP_EXPIRATION_IN_MINUTES as string
						) *
							60000
				).getTime() < new Date().getTime()
			) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "OTP expired. Please resend and try again"
				})
			}
			// check secret key will we receive secret key??

			// update data 
			await User.findByIdAndUpdate(listUserData.userId, {
				password: encryptPassword,
				isVerified:false
			})
			
			return response.successResponse({
				message: `Password updated successfully`
			})
		} catch (error) {
			next(error)
		}
	}

	public async signIn(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			const inputData: SignInPayload = req.body

			//check if user exist
			const userExists = await User.findOne({
				email: inputData.email,
				roleId: inputData.roleId,
				isDeleted: false,
				isActive: true
			})
			if (!userExists) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "User not found"
				})
			}

			const isValidPassword: boolean = await bcrypt.compare(
				inputData.password,
				userExists.password
			)
			if (!isValidPassword) {
				return response.errorResponse({
					statusCode: 401,
					message: "Email or password mismatch"
				})
			}

			await User.findByIdAndUpdate(userExists._id, {
				lastActivatedOn: moment().format("YYYY-MM-DD")
			})

			// generate token
			const token: string = jwt.sign(
				{
					userId: userExists._id,
					email: userExists.email
				},
				process.env.JWT_SECRET_KEY as string,
				{
					expiresIn: process.env.JWT_TOKEN_EXPIRATION as string
				}
			)

			const data = {
				_id: userExists._id,
				name: userExists.name,
				roleId: userExists.roleId,
				email: userExists.email,
				mobile: userExists.mobile
			}

			return response.successResponse({token, data})
		} catch (error) {
			next(error)
		}
	}

	public async refreshToken(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			let accessToken: string = req.headers.authorization as string
			if (!accessToken) {
				return response.errorResponse({
					statusCode: 401,
					message: "Missing authorize header"
				})
			}

			// @ts-ignore
			accessToken = accessToken.split("Bearer").pop().trim()

			const decodedToken = jwt.decode(accessToken)
			if (!decodedToken) {
				return response.errorResponse({
					statusCode: 401,
					message: "Not a valid access token"
				})
			}

			// @ts-ignore
			delete decodedToken.iat
			// @ts-ignore
			delete decodedToken.exp
			// @ts-ignore
			delete decodedToken.nbf
			// @ts-ignore
			delete decodedToken.jti

			// generate new token
			const token: string = jwt.sign(
				// @ts-ignore
				decodedToken,
				process.env.JWT_SECRET_KEY as string,
				{
					expiresIn: process.env.JWT_TOKEN_EXPIRATION as string
				}
			)

			return response.successResponse({
				message: `Refresh token generated successfully`,
				token
			})
		} catch (error) {
			next(error)
		}
	}
}

export default new AuthController()
