import {Range, OrderDir} from "./common"

export type UserTableData = {
	name: string
	email: string
	roleId: number
	mobile: string
	password: string
	dob: string
	address: string
	city: string
	state: string
	country: string
	postalCode: string
	secrectCode: string
	lastActivatedOn: string
	isVerified: boolean
	isActive: boolean
	isDeleted: boolean
} & Range & OrderDir

export type UserDetails = Omit<UserTableData, "password">

export type UserShortDetails= {
	userId: string
} & Partial<{
	name: string
	email: string
	roleId: number
	mobile: string
	password: string
	dob: string
	address: string
	city: string
	state: string
	country: string
	postalCode: string
	secrectCode: string
	lastActivatedOn: string
	isVerified: boolean
	isActive: boolean
	isDeleted: boolean
	createdAt: string
}>

export type UserCreateApiPayload = {
	name: string
	email: string
	roleId: number
	password: string
	city: string
	state: string
	country: string
	postalCode: string
} & Partial <{
	mobile: string
	dob: string
	address: string
	secrectCode: string
	lastActivatedOn: string
	isVerified: boolean
	isActive: boolean
	isDeleted: boolean
}>

export type UserUpdatePayload = {
	userId: string
} & Partial<{
	name: string
	email: string
	roleId: number
	mobile: string
	password: string
	dob: string
	address: string
	city: string
	state: string
	country: string
	postalCode: string
	secrectCode: string
	lastActivatedOn: string
	isVerified: boolean
	isActive: boolean
	isDeleted: boolean
}>