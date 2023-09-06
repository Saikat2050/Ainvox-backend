import {OrderDir, Range} from "./common"

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

export type SignOutPayload = {
	userId: string
}

export type UpdateUserPayload = {
	userId: string
	name?: string
	email?: {
		email: string
		password: string
	}
	mobile?: string
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

export type VerifyOtpPayload = {
	email: string
	value: string
}

export type ResetPasswordPayload = {
	email: string
	value: string
	password: string
}

type FilterPayload = {
	userId?: string
	search?: string
}

export type ListUserPayload = {
	filter?: FilterPayload
	range?: Range
	sort?: {
		orderBy?: "userId"
		orderDir?: OrderDir
	}
}

export type DeleteUserPayload = {
	userId: string
}
