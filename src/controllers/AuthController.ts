// import {Request, Response, NextFunction} from "express"
// import moment from "moment"
// import bcrypt from "bcrypt"
// import jwt from "jsonwebtoken"

// import {Headers} from "../types/common"
// import {
// 	VerificationFor,
// 	LogInWith,
// 	VerificationDetails,
// 	CredentialDetails,
// 	SignInPayload,
// 	VerifyOtpPayload,
// 	ResetPasswordPayload,
// 	CreateCredentialPayload,
// 	DecryptData,
// 	VerificationTableData,
// 	Role,
// 	UserData,
// 	Hash
// } from "../types/auth"
// import {UserShortDetails, CreateDefaultUserPayload} from "../types/users"
// import {
// 	CreateClientApiPayload,
// 	ClientDetails,
// 	AdminUserDetails
// } from "../types/clients"
// import CommonModel from "../models/CommonModel"
// import CustomModel from "../models/CustomModel"
// import helper, {
// 	generateOtp,
// 	sendSMS,
// 	sendOtpToEmail,
// 	decryptBycrypto
// } from "../helpers/helper"
// import {BadRequestException, UnauthorizedException} from "../lib/exceptions"

// class AuthController {
// 	private commonModel
// 	private authCredentialModel
// 	private customModel
// 	private verificationCommonModel
// 	private loginHistoriesModel
// 	private clientModel
// 	private idColumn: string = "userId"
// 	private authCredentialIdColumn: string = "credentialId"
// 	private verificationIdColumn: string = "verificationId"
// 	private loginHistoriesIdColumn: string = "logInHistoriesId"
// 	private clientIdColumn: string = "clientId"

// 	constructor() {
// 		this.commonModel = new CommonModel("userDetails", this.idColumn, [
// 			"firstName",
// 			"middleName",
// 			"lastName",
// 			"gender",
// 			"city",
// 			"state",
// 			"country",
// 			"postal",
// 			"email",
// 			"mobile"
// 		])
// 		this.authCredentialModel = new CommonModel(
// 			"authCredential",
// 			this.authCredentialIdColumn,
// 			[]
// 		)
// 		this.verificationCommonModel = new CommonModel(
// 			"verification",
// 			this.verificationIdColumn,
// 			[]
// 		)
// 		this.loginHistoriesModel = new CommonModel(
// 			"logInHistories",
// 			this.loginHistoriesIdColumn,
// 			[]
// 		)
// 		this.clientModel = new CommonModel("clientDetails", this.clientIdColumn, [])
// 		this.customModel = new CustomModel("clientDetails", this.clientIdColumn, [])

// 		this.register = this.register.bind(this)
// 		this.sendOtpWithHash = this.sendOtpWithHash.bind(this)
// 		this.verifyingByHashOtp = this.verifyingByHashOtp.bind(this)
// 		this.resetPassword = this.resetPassword.bind(this)
// 		this.signIn = this.signIn.bind(this)
// 		this.loginAs = this.loginAs.bind(this)
// 		this.refreshToken = this.refreshToken.bind(this)
// 	}

// 	public async register(req: Request, res: Response, next: NextFunction) {
// 		try {
// 			let inputData: CreateClientApiPayload = req.body

// 			const [isValidEmail, isValidPhone, isValidPassword, isUserEmailValid]: [
// 				boolean,
// 				boolean,
// 				boolean,
// 				boolean
// 			] = await Promise.all([
// 				// email validation
// 				helper.regexEmail(inputData.email),

// 				// phone validation
// 				inputData.phone ? helper.regexMobile(inputData.phone) : false,

// 				// user email validation
// 				helper.regexEmail(inputData.userDetails.email),

// 				// password validation
// 				helper.regexPassword(inputData.userDetails.password)
// 			])
// 			if (!isValidEmail) {
// 				throw new BadRequestException("Email not valid!")
// 			}
// 			if (inputData.phone && !isValidPhone) {
// 				throw new BadRequestException("Phone number not valid!")
// 			}
// 			if (!isUserEmailValid) {
// 				throw new BadRequestException("User email not valid!")
// 			}
// 			if (!isValidPassword) {
// 				throw new BadRequestException("Password must be more then 8 char!")
// 			}

// 			const [emailExists, phoneExists, userExists]: [
// 				ClientDetails[],
// 				ClientDetails[],
// 				AdminUserDetails[]
// 			] = await Promise.all([
// 				this.clientModel.list({
// 					email: inputData.email
// 				}),
// 				inputData?.phone
// 					? this.clientModel.list({
// 							phone: inputData.phone
// 					  })
// 					: [],
// 				this.commonModel.list({
// 					email: inputData.userDetails.email
// 				})
// 			])
// 			if (emailExists.length) {
// 				throw new BadRequestException("Email already exists")
// 			}
// 			if (inputData.phone && phoneExists?.length) {
// 				throw new BadRequestException("Phone number already exists")
// 			}
// 			if (userExists.length) {
// 				throw new BadRequestException("User email already exists")
// 			}

// 			// hashing password
// 			inputData.userDetails.password = await bcrypt.hash(
// 				inputData.userDetails.password,
// 				parseInt(process.env.SALT_ROUNDS as string)
// 			)

// 			const {userDetails, ...payload} = inputData

// 			// create client
// 			const [data]: ClientDetails[] = await this.clientModel.bulkCreate([
// 				payload
// 			])

// 			// default user creation
// 			const userPayload: CreateDefaultUserPayload = {
// 				clientId: data.clientId,
// 				firstName: userDetails.firstName,
// 				roleId: Role.ADMIN,
// 				email: userDetails.email
// 			}

// 			const [user]: UserShortDetails[] = await this.commonModel.bulkCreate([
// 				userPayload
// 			])

// 			// create auth details
// 			const authCredentials: CreateCredentialPayload[] = [
// 				{
// 					userId: user.userId,
// 					userName: user.email,
// 					password: userDetails.password,
// 					logInWith: LogInWith.EMAIL
// 				}
// 			]
// 			await this.authCredentialModel.bulkCreate(authCredentials)

// 			// encryption data
// 			const hashString = await helper.encryptionByCrypto({
// 				userId: user.userId,
// 				email: user.email
// 			})
// 			const link: string = `${process.env.BASE_URL_API}?hash=${hashString}`

// 			// send verification mail
// 			await helper.sendVerificationEmail(
// 				user.email,
// 				link,
// 				`${user.firstName} ${user.middleName ?? ""} ${user.lastName ?? ""}`
// 			)

// 			return res.json({
// 				success: true,
// 				message: `Client created successfully`,
// 				data
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}

// 	public async sendOtp(req: Request, res: Response, next: NextFunction) {
// 		try {
// 			const {userName}: {userName: string} = req.body

// 			//check if user exist
// 			const [authCredential]: CredentialDetails[] =
// 				await this.authCredentialModel.list({
// 					userName
// 				})
// 			if (!authCredential) {
// 				throw new UnauthorizedException("User not found")
// 			}

// 			// generate otp
// 			const otp: number = await generateOtp()

// 			// create encryption
// 			const encryptedOtp: string = jwt.sign(
// 				{
// 					otp
// 				},
// 				process.env.JWT_SECRET_KEY as string
// 			)

// 			// save encrypted otp
// 			const verificationDataExists: VerificationDetails[] =
// 				await this.verificationCommonModel.list({value: userName})
// 			if (!verificationDataExists || !verificationDataExists?.length) {
// 				await this.verificationCommonModel.bulkCreate([
// 					{
// 						verificationType: authCredential.logInWith,
// 						value: userName,
// 						otp: encryptedOtp,
// 						isVerified: false,
// 						verificationFor: VerificationFor.AUTH
// 					}
// 				])
// 			} else {
// 				await this.verificationCommonModel.update(
// 					{otp: encryptedOtp},
// 					verificationDataExists[0]?.verificationId
// 				)
// 			}

// 			// get first name of the user
// 			const [userDetails]: UserShortDetails[] = await this.commonModel.list({
// 				userId: authCredential.userId
// 			})
// 			if (!userDetails) {
// 				throw new UnauthorizedException("User not found")
// 			}

// 			if (authCredential.logInWith === LogInWith.MOBILE) {
// 				// send sms
// 				// await sendSMS(authCredential[0].mobile, otp);
// 			} else if (authCredential.logInWith === LogInWith.EMAIL) {
// 				// send otp to email
// 				await sendOtpToEmail(
// 					authCredential.userName,
// 					otp,
// 					userDetails.firstName
// 				)
// 			}

// 			return res.json({
// 				success: true,
// 				message: `OTP sent successfully`
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}

// 	public async sendOtpWithHash(
// 		req: Request,
// 		res: Response,
// 		next: NextFunction
// 	) {
// 		try {
// 			const {hash}: Hash = req.body

// 			// decrypt hash
// 			const decryptData: DecryptData = await decryptBycrypto(hash)
// 			const {email, userId}: DecryptData = decryptData

// 			// check if user exists
// 			const [userDetails]: UserShortDetails[] = await this.commonModel.list({
// 				userId
// 			})
// 			if (!userDetails) {
// 				throw new UnauthorizedException("User not found")
// 			}

// 			// generate otp
// 			const otp: number = await generateOtp()

// 			// create encryption
// 			const encryptedOtp: string = jwt.sign(
// 				{otp},
// 				process.env.JWT_SECRET_KEY as string
// 			)

// 			// delete existing non-verified entries
// 			await this.verificationCommonModel.softDeleteByFilter(
// 				{
// 					value: email,
// 					isVerified: false
// 				},
// 				userId
// 			)

// 			await this.verificationCommonModel.bulkCreate([
// 				{
// 					verificationType: LogInWith.EMAIL,
// 					value: email,
// 					isVerified: false,
// 					verificationFor: VerificationFor.AUTH,
// 					otp: encryptedOtp
// 				}
// 			])

// 			// send otp to email
// 			await sendOtpToEmail(email, otp, userDetails.firstName)

// 			return res.json({
// 				success: true,
// 				message: `OTP sent successfully`
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}

// 	public async verifyingByHashOtp(
// 		req: Request,
// 		res: Response,
// 		next: NextFunction
// 	) {
// 		try {
// 			const {hash, otp}: {hash: string; otp: number} = req.body
// 			const decryptData: DecryptData = await decryptBycrypto(hash)
// 			const {email, userId}: DecryptData = decryptData

// 			// check if otp is valid
// 			const [verificationData]: VerificationTableData[] =
// 				await this.verificationCommonModel.list({
// 					value: email,
// 					isVerified: false,
// 					verificationType: LogInWith.EMAIL,
// 					verificationFor: VerificationFor.AUTH,
// 					status: true
// 				})
// 			if (!verificationData) {
// 				throw new UnauthorizedException("User not found")
// 			}

// 			let decoded: any = null
// 			try {
// 				decoded = jwt.verify(
// 					(verificationData?.otp).toString(),
// 					process.env.JWT_SECRET_KEY as string
// 				)
// 			} catch (error) {
// 				throw new UnauthorizedException(
// 					"Invalid OTP. Please resend and try again."
// 				)
// 			}
// 			if (parseInt(decoded?.otp) !== parseInt(otp.toString())) {
// 				throw new UnauthorizedException(
// 					"Invalid OTP. Please resend and try again."
// 				)
// 			}
// 			if (
// 				new Date(
// 					new Date(verificationData.createdAt.toString()).getTime() +
// 						parseInt(process.env.OTP_EXPIRATION_IN_MINUTES as string) * 60000
// 				).getTime() < new Date().getTime()
// 			) {
// 				throw new UnauthorizedException(
// 					"OTP expired. Please resend and try again."
// 				)
// 			}

// 			// mark OTP as used
// 			await this.verificationCommonModel.update(
// 				{isVerified: true},
// 				verificationData.verificationId
// 			)

// 			return res.json({
// 				success: true,
// 				message: `OTP verified successfully`
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}

// 	public async resetPassword(req: Request, res: Response, next: NextFunction) {
// 		try {
// 			let {hash, otp, password}: ResetPasswordPayload = req.body

// 			// encrypt password
// 			const isValidPassword: boolean = await helper.regexPassword(password)
// 			if (!isValidPassword) {
// 				throw new BadRequestException(
// 					"Password must be more then 8 char!",
// 					"validation_error"
// 				)
// 			}
// 			password = await bcrypt.hash(
// 				password,
// 				parseInt(process.env.SALT_ROUNDS as string)
// 			)

// 			const decryptData: DecryptData = await decryptBycrypto(hash)
// 			const {email, userId} = decryptData

// 			// check if user & verification exist
// 			const [[authCredential], [verificationData]]: [
// 				CredentialDetails[],
// 				VerificationTableData[]
// 			] = await Promise.all([
// 				// authCredential
// 				this.authCredentialModel.list({userName: email}),

// 				// verification
// 				this.verificationCommonModel.list({
// 					value: email,
// 					isVerified: false,
// 					verificationType: LogInWith.EMAIL,
// 					verificationFor: VerificationFor.AUTH,
// 					status: true
// 				})
// 			])
// 			if (!authCredential) {
// 				throw new UnauthorizedException("User not found")
// 			}
// 			if (!verificationData) {
// 				throw new UnauthorizedException(
// 					"Invalid OTP. Please resend and try again."
// 				)
// 			}

// 			// check if otp is valid
// 			let decoded: any = null
// 			try {
// 				decoded = jwt.verify(
// 					(verificationData?.otp).toString(),
// 					process.env.JWT_SECRET_KEY as string
// 				)
// 			} catch (error) {
// 				throw new UnauthorizedException(
// 					"Invalid OTP. Please resend and try again."
// 				)
// 			}
// 			if (parseInt(decoded?.otp) !== parseInt(otp.toString())) {
// 				throw new UnauthorizedException(
// 					"Invalid OTP. Please resend and try again."
// 				)
// 			}
// 			if (
// 				new Date(
// 					new Date(verificationData.createdAt.toString()).getTime() +
// 						parseInt(process.env.OTP_EXPIRATION_IN_MINUTES as string) * 60000
// 				).getTime() < new Date().getTime()
// 			) {
// 				throw new UnauthorizedException(
// 					"OTP expired. Please resend and try again."
// 				)
// 			}

// 			await Promise.all([
// 				// update otp
// 				this.verificationCommonModel.update(
// 					{isVerified: true},
// 					verificationData.verificationId
// 				),

// 				// update password
// 				this.authCredentialModel.update({password}, authCredential.credentialId)
// 			])

// 			return res.json({
// 				success: true,
// 				message: `Password updated successfully`
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}

// 	public async signIn(req: Request, res: Response, next: NextFunction) {
// 		try {
// 			const inputData: SignInPayload = req.body

// 			// check if userName is valid
// 			const [authCredential]: CredentialDetails[] =
// 				await this.authCredentialModel.list({
// 					userName: inputData.userName
// 				})
// 			if (!authCredential) {
// 				throw new UnauthorizedException("User not found")
// 			}

// 			// check if user is valid
// 			const [verificationData]: VerificationDetails[] =
// 				await this.verificationCommonModel.list({
// 					verificationType: authCredential.logInWith,
// 					value: inputData.userName
// 				})
// 			if (!verificationData?.isVerified) {
// 				throw new UnauthorizedException("User is not verified")
// 			}

// 			const isValidPassword: boolean = await bcrypt.compare(
// 				inputData.password,
// 				authCredential?.password
// 			)
// 			if (!isValidPassword) {
// 				throw new UnauthorizedException("Incorrect password")
// 			}

// 			await Promise.all([
// 				// update lastActiveOn
// 				this.commonModel.update(
// 					{lastActiveOn: moment().format("YYYY-MM-DD")},
// 					authCredential.userId
// 				),

// 				// log-in history
// 				this.loginHistoriesModel.bulkCreate([
// 					{
// 						userId: authCredential.userId,
// 						logInWith: authCredential.logInWith
// 					}
// 				])
// 			])

// 			// generate token
// 			const token: string = jwt.sign(
// 				{
// 					userId: authCredential.userId,
// 					// @ts-ignore
// 					email: authCredential.email
// 				},
// 				process.env.JWT_SECRET_KEY as string,
// 				{
// 					expiresIn: process.env.JWT_TOKEN_EXPIRATION as string
// 				}
// 			)

// 			const [data]: UserShortDetails[] = await this.commonModel.list({
// 				userId: authCredential.userId
// 			})

// 			return res.json({
// 				success: true,
// 				message: `Sign-in successeful`,
// 				token,
// 				data
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}

// 	public async loginAs(req: Request, res: Response, next: NextFunction) {
// 		try {
// 			const {clientId}: Headers = req.body

// 			const [userData]: UserData = await this.customModel.loginAs(clientId)

// 			await Promise.all([
// 				// update lastActiveOn
// 				this.commonModel.update(
// 					{lastActiveOn: moment().format("YYYY-MM-DD")},
// 					userData.userId
// 				),

// 				// log-in history
// 				this.loginHistoriesModel.bulkCreate([
// 					{
// 						userId: userData.userId,
// 						logInWith: LogInWith.EMAIL
// 					}
// 				])
// 			])

// 			// generate token
// 			const token: string = jwt.sign(
// 				{
// 					userId: userData.userId.toString()
// 				},
// 				process.env.JWT_SECRET_KEY as string,
// 				{
// 					expiresIn: process.env.JWT_TOKEN_EXPIRATION as string
// 				}
// 			)

// 			const [data]: UserShortDetails[] = await this.commonModel.list({
// 				userId: userData.userId
// 			})

// 			return res.json({
// 				success: true,
// 				message: `Sign-in successful`,
// 				token,
// 				data
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}

// 	public async refreshToken(req: Request, res: Response, next: NextFunction) {
// 		try {
// 			let accessToken: string = req.headers.authorization as string
// 			if (!accessToken) {
// 				throw new BadRequestException(
// 					"Missing authorization header",
// 					"invalid_token"
// 				)
// 			}

// 			// @ts-ignore
// 			accessToken = accessToken.split("Bearer").pop().trim()

// 			let decodedToken = jwt.decode(accessToken)
// 			if (!decodedToken) {
// 				throw new BadRequestException("Invalid token", "invalid_token")
// 			}

// 			// @ts-ignore
// 			delete decodedToken.iat
// 			// @ts-ignore
// 			delete decodedToken.exp
// 			// @ts-ignore
// 			delete decodedToken.nbf
// 			// @ts-ignore
// 			delete decodedToken.jti

// 			// generate new token
// 			const token: string = jwt.sign(
// 				// @ts-ignore
// 				decodedToken,
// 				process.env.JWT_SECRET_KEY as string,
// 				{
// 					expiresIn: process.env.JWT_TOKEN_EXPIRATION as string
// 				}
// 			)

// 			return res.json({
// 				success: true,
// 				message: `Refresh token generated successfully`,
// 				token
// 			})
// 		} catch (error) {
// 			res.status(400).json({
// 				status: 400,
// 				message: error?.toString(),
// 				code: "unexpected_error"
// 			})
// 			return
// 		}
// 	}
// }

// export default new AuthController()
