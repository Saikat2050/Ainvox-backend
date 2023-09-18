import {Request, Response, NextFunction} from "express"
import User from "../models/users"
import bcrypt from "bcrypt"

import errorData from "../constants/errorData.json"

import {UserDetails, UserUpdatePayload, ListUserPayload} from "../types/users"
import {ApiResponse} from "../helpers/ApiResponse"

class AuthController {
	constructor() {
		this.list = this.list.bind(this)
		this.update = this.update.bind(this)
		this.delete = this.delete.bind(this)
	}

	public async update(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			let {userId, ...inputData}: UserUpdatePayload = req.body

			const listUserData = await User.findById(userId)
			if (!listUserData) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "User not found"
				})
			}

			// update
			if (req.body.email) {
				inputData.email = req.body.email.email
				inputData.isVerified = false

				const isValidPassword: boolean = await bcrypt.compare(
					req.body.email.password,
					listUserData.password
				)
				if (!isValidPassword) {
					return response.errorResponse({
						statusCode: 401,
						message: "Unauthorized"
					})
				}
			}
			await User.findByIdAndUpdate(userId, inputData)

			return response.successResponse({
				message: "User updated successfully"
			})
		} catch (error) {
			next(error)
		}
	}

	public async list(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			const {filter, range, sort}: ListUserPayload = req.body

			let filterObject: any = {}
			let sortObject: any = {}
			let limit: number = 100 // page size
			let skip: number = 0 // page - 1

			// filter
			if (filter?.userId) {
				filterObject._id = filter.userId
			}
			if (filter?.search) {
				filterObject.name = new RegExp(`/${filter.search}/`, "g")
			}

			// sort
			if (sort) {
				sortObject[`${sort.orderBy}`] = sort.orderDir ?? 1
			}
			sortObject.createdAt = -1

			// range
			if (range?.pageSize) {
				limit = Number(range.pageSize)
			}
			if (range?.page) {
				const page = Number(range?.page) - 1
				skip = Number(limit * page)
			}

			const data = User.find(filterObject)
				.sort(sortObject)
				.skip(skip)
				.limit(limit)

			return response.successResponse({
				message: "User List fetched successfully",
				data
			})
		} catch (error) {
			next(error)
		}
	}

	public async delete(req: Request, res: Response, next: NextFunction) {
		try {
			const response = new ApiResponse(res)
			const userId: string = req.body.userId

			// check if user exist
			const userDetails = await User.findById(userId)

			if (!userDetails) {
				return response.errorResponse({
					...errorData.NOT_FOUND,
					message: "User not found"
				})
			}

			const isValidPassword: boolean = await bcrypt.compare(
				req.body.password,
				userDetails.password
			)
			if (!isValidPassword) {
				return response.errorResponse({
					statusCode: 401,
					message: "Unauthorized"
				})
			}

			// delete
			await User.findByIdAndUpdate(userId, {isDeleted: true})

			return response.successResponse({
				message: `User deleted successfully`
			})
		} catch (error) {
			next(error)
		}
	}
}

export default new AuthController()
