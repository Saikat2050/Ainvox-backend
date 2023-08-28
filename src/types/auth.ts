import {Manipulator, Timestamp} from "./common"

export enum Role {
	SUPER_ADMIN = 1,
	FREELANCER = 2,
	CLIENT = 3
}

export type CredentialDetails = {
	credentialId: number
	userId: number
	userName: string
	password: string
	status: boolean
}

export type CreateCredentialPayload = {
	userId: number
	userName: string
	password: string
}

export type SignInPayload = {
	userName: string
	password: string
}

export type VerifyOtpPayload = {
	userName?: string
	hash?: string
	otp: number
}

export type SendOtpPayload = {
	userName: string
}