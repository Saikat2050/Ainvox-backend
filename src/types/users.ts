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
}

export type UserDetails = Omit<UserTableData, "password">
