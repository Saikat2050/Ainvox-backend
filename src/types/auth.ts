export enum Role {
	SUPER_ADMIN = 1,
	FREELANCER = 2,
	CLIENT = 3
}

export type SignInPayload = {
	email: string
	roleId: number
	password: string
}

export type RegisterPayload = {
	name: string
	email: string
	roleId: number
	mobile?: string
	password: string
	dob?: string
	address?: string
	city?: string
	state?: string
	country?: string
	postalCode?: string
}

export type SendOtpPayload = {
	email: string
}

export type ResetPasswordPayload = {
	email: string
	otp: string
	password: string
}

export type verifyOtpPayload = {
	email: string
	otp: string
}

export type SecrectCodeSchema = {
	otp: string
	expireIn: string
}
