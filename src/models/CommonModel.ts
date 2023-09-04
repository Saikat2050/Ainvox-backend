// import moment from "moment"

// import {DBHelper} from "../lib/DBHelper"
// import {Role} from "../types/auth"
// import {Range, Sort} from "../types/common"

// export default class CommonModel {
// 	private TABLE_NAME: string
// 	private ID_COLUMN_NAME: string
// 	private SEARCH_COLUMN_NAME: string[]

// 	constructor(
// 		tableName: string,
// 		idColumnName: string,
// 		searchColumnName: string[]
// 	) {
// 		this.TABLE_NAME = tableName
// 		this.ID_COLUMN_NAME = idColumnName
// 		this.SEARCH_COLUMN_NAME = searchColumnName
// 	}

// 	list = async (
// 		filter: any,
// 		range?: Range,
// 		sort?: Sort,
// 		fields?: string[],
// 		isCount?: boolean,
// 		filterNotToBeIncluded?: any,
// 		customFilters?: string[]
// 	): Promise<any> => {
// 		const providersFactory = new DBHelper()
// 		const {query, release} = await providersFactory.transaction()

// 		try {
// 			query("BEGIN")
// 			// filters
// 			let whereArr: string[] = [`"deletedAt" IS NULL`]

// 			if (filter && Object.keys(filter).length) {
// 				Object.keys(filter).map((column) => {
// 					if (
// 						filter[column] === undefined ||
// 						filter[column] === null ||
// 						String(filter[column]).trim() === ""
// 					) {
// 						return
// 					}
// 					if (column === "createdAt") {
// 						if (moment(filter[column]).isValid()) {
// 							whereArr.push(
// 								`"${column}"::date = '${moment(filter[column]).format(
// 									"YYYY-MM-DD"
// 								)}'`
// 							)
// 						}
// 					} else if (column === "search") {
// 						let whereSearch: string[] = this.SEARCH_COLUMN_NAME.map((el) => {
// 							return `"${el}" ILIKE '%${filter[column]}%'`
// 						})
// 						whereArr.push(`(${whereSearch.join(" OR ")})`)
// 					} else {
// 						switch (typeof filter[column] as string) {
// 							case "number":
// 								whereArr.push(`"${column}" = ${filter[column]}`)
// 								break
// 							case "object":
// 								if (Array.isArray(filter[column])) {
// 									whereArr.push(
// 										`"${column}" IN (${
// 											typeof filter[column][0] === "string"
// 												? `'${filter[column].join("', '")}'`
// 												: `${filter[column].join(", ")}`
// 										})`
// 									)
// 								}
// 								break
// 							default:
// 								whereArr.push(`"${column}" = '${filter[column]}'`)
// 						}
// 					}
// 				})
// 			}

// 			if (filterNotToBeIncluded && Object.keys(filterNotToBeIncluded).length) {
// 				Object.keys(filterNotToBeIncluded).map((column) => {
// 					if (
// 						filterNotToBeIncluded[column] === undefined ||
// 						filterNotToBeIncluded[column] === null ||
// 						String(filterNotToBeIncluded[column]).trim() === ""
// 					) {
// 						return
// 					}

// 					if (column === "createdAt") {
// 						whereArr.push(
// 							`"${column}"::date != '${filterNotToBeIncluded[column]}'`
// 						)
// 					} else {
// 						switch (typeof filterNotToBeIncluded[column] as string) {
// 							case "number":
// 								whereArr.push(`"${column}" != ${filterNotToBeIncluded[column]}`)
// 								break
// 							case "object":
// 								if (Array.isArray(filterNotToBeIncluded[column])) {
// 									whereArr.push(
// 										`"${column}" NOT IN (${
// 											typeof filterNotToBeIncluded[column][0] === "string"
// 												? `'${filterNotToBeIncluded[column].join("', '")}'`
// 												: `${filterNotToBeIncluded[column].join(", ")}`
// 										})`
// 									)
// 								}
// 								break
// 							default:
// 								whereArr.push(
// 									`"${column}" != '${filterNotToBeIncluded[column]}'`
// 								)
// 						}
// 					}
// 				})
// 			}

// 			if (customFilters?.length) {
// 				whereArr = whereArr.concat(customFilters)
// 			}

// 			// pagination
// 			let limit: number = 100
// 			let offset: number = 0
// 			if (range) {
// 				range.page = range.page ? range.page : 1
// 				limit = range.pageSize ?? limit
// 				offset = (range.page - 1) * limit
// 			}

// 			// sorting
// 			let sortArr: string[] = []
// 			if (sort && Object.keys(sort).length > 0) {
// 				sortArr.push(
// 					`"${sort["orderBy"]}" ${
// 						sort["orderDir"]?.toString()?.toUpperCase() ?? "ASC"
// 					}`
// 				)
// 			}

// 			sortArr.push(`"createdAt" DESC`)

// 			let sqlFields
// 			if (fields) {
// 				if (fields.length > 0) {
// 					if (!isCount) {
// 						sqlFields = `"${fields.join('", "')}"`
// 					} else {
// 						sqlFields = `${fields[0]}`
// 					}
// 				}
// 			} else {
// 				sqlFields = `*`
// 			}

// 			let sql: string = `
//                       SELECT ${sqlFields}
//                       FROM "${this.TABLE_NAME}"
//                       WHERE ${whereArr.join(" AND ")}
//                   `
// 			if (!isCount) {
// 				sql += `
//           ORDER BY ${sortArr.join(", ")}
//           LIMIT ${limit} OFFSET ${offset}
//           `
// 			}
// 			const {rows} = await query(sql)
// 			query("COMMIT")

// 			release()
// 			return rows
// 		} catch (error) {
// 			query("ROLLBACK")

// 			release()
// 			throw error
// 		}
// 	}

// 	bulkCreate = async (inputData: any, createdBy?: number) => {
// 		const providersFactory = new DBHelper()
// 		const {query, release} = await providersFactory.transaction()
// 		try {
// 			// for admin users
// 			if (!createdBy) {
// 				const superAdmin = await query(`
// 				SELECT *
// 				FROM "userDetails"
// 				WHERE "roleId" = ${Role.SUPER_ADMIN}
// 					AND "deletedAt" IS NULL
// 			`)

// 				if (superAdmin.rows.length > 0) {
// 					createdBy = superAdmin.rows[0].userId
// 				}
// 			}

// 			if (createdBy) {
// 				// @ts-ignore
// 				inputData = inputData.map((el) => {
// 					el[`createdBy`] = createdBy

// 					return el
// 				})
// 			}

// 			// handle insert data
// 			for (let i = 0; i < inputData.length; i++) {
// 				if (Object.keys(inputData[i]).length) {
// 					Object.keys(inputData[i]).forEach((el) => {
// 						// @ts-ignore
// 						if (
// 							!inputData[i][el] ||
// 							(typeof inputData[i][el] === "string" &&
// 								inputData[i][el].trim() === "")
// 						) {
// 							// @ts-ignore
// 							delete inputData[i][el]
// 						} else if (typeof inputData[i][el] === "string") {
// 							inputData[i][el] = inputData[i][el].trim()
// 						}
// 					})
// 				}
// 			}

// 			let sql = `INSERT INTO "${this.TABLE_NAME}" ("${Object.keys(
// 				inputData[0]
// 			).join('", "')}") VALUES `
// 			let commonDataArr: any[] = []

// 			// looping through values
// 			for (let i = 0; i < inputData.length; i++) {
// 				commonDataArr.push(
// 					`('${Object.values(inputData[i])
// 						.map((el) => el)
// 						.join("', '")}')`
// 				)
// 			}
// 			sql += commonDataArr.join(", ")
// 			sql += `RETURNING *`

// 			// executing query
// 			const {rows} = await query(sql)
// 			query("COMMIT")

// 			release()
// 			// return rows
// 			return rows
// 		} catch (error) {
// 			query("ROLLBACK")

// 			release()
// 			throw error
// 		}
// 	}

// 	update = async (data: any, id: number, updatedBy?: number): Promise<any> => {
// 		const providersFactory = new DBHelper()
// 		const {query, release} = await providersFactory.transaction()

// 		try {
// 			// for admin users
// 			if (!updatedBy) {
// 				const superAdmin = await query(`
// 				SELECT *
// 				FROM "userDetails"
// 				WHERE "roleId" = ${Role.SUPER_ADMIN}
// 					AND "deletedAt" IS NULL
// 			`)

// 				if (superAdmin.rows.length > 0) {
// 					updatedBy = superAdmin.rows[0].userId
// 				}
// 			}

// 			let updateArr: string[] = []
// 			Object.keys(data).forEach((column) => {
// 				// looping through values
// 				if (
// 					(typeof data[column] !== "boolean" && !data[column]) ||
// 					(typeof data[column] === "string" && data[column].trim() === "")
// 				) {
// 					// @ts-ignore
// 					delete data[column]
// 				} else {
// 					if (typeof data[column] === "string") {
// 						data[column] = data[column].trim()
// 					}

// 					let value =
// 						["number", "boolean"].indexOf(typeof data[column]) >= 0
// 							? data[column]
// 							: `'${data[column]}'`
// 					updateArr.push(`"${column}" = ${value}`)
// 				}
// 			})

// 			query("BEGIN")
// 			let sql: string = `
//       			UPDATE "${this.TABLE_NAME}"
//       			SET ${updateArr.join(", ")} ${updateArr?.length > 0 ? "," : ""}
//       			"updatedAt"='NOW()'${updatedBy ? `, "updatedBy" = '${updatedBy}'` : ""}
//       			WHERE "deletedAt" IS NULL
//       			AND "${this.ID_COLUMN_NAME}" = '${id}'
//      			 `
// 			sql += `RETURNING *`
// 			const {rows} = await query(sql)
// 			query("COMMIT")
// 			release()

// 			return rows
// 		} catch (error) {
// 			query("ROLLBACK")

// 			release()
// 			throw error
// 		}
// 	}

// 	softDelete = async (
// 		id: number[],
// 		deletedBy?: number,
// 		fieldName?: string
// 	): Promise<any> => {
// 		const providersFactory = new DBHelper()
// 		const {query, release} = await providersFactory.transaction()
// 		try {
// 			// for admin users
// 			if (!deletedBy) {
// 				const superAdmin = await query(`
// 				SELECT *
// 				FROM "userDetails"
// 				WHERE "roleId" = ${Role.SUPER_ADMIN}
// 					AND "deletedAt" IS NULL
// 			`)

// 				if (superAdmin.rows.length > 0) {
// 					deletedBy = superAdmin.rows[0].userId
// 				}
// 			}

// 			query("BEGIN")
// 			const sql: string = `
//       		UPDATE "${this.TABLE_NAME}"
//       		SET "deletedAt" = 'NOW()'${
// 						deletedBy ? `, "deletedBy" = '${deletedBy}'` : ""
// 					}
//       		WHERE "${fieldName ?? this.ID_COLUMN_NAME}" IN (${id.join(", ")})
//       		`
// 			const {rows} = await query(sql)
// 			query("COMMIT")
// 			release()
// 			return rows
// 		} catch (error) {
// 			query("ROLLBACK")
// 			release()
// 			throw error
// 		}
// 	}

// 	softDeleteByFilter = async (
// 		filters: any,
// 		deletedBy?: number
// 	): Promise<any> => {
// 		const providersFactory = new DBHelper()
// 		const {query, release} = await providersFactory.transaction()
// 		try {
// 			// for admin users
// 			if (!deletedBy) {
// 				const superAdmin = await query(`
// 				SELECT *
// 				FROM "userDetails"
// 				WHERE "roleId" = ${Role.SUPER_ADMIN}
// 					AND "deletedAt" IS NULL
// 			`)

// 				if (superAdmin.rows.length > 0) {
// 					deletedBy = superAdmin.rows[0].userId
// 				}
// 			}
// 			let whereArr: any[] = []
// 			Object.keys(filters).forEach((column) => {
// 				// looping through values
// 				switch (typeof filters[column] as string) {
// 					case "number":
// 						whereArr.push(`"${column}" = ${filters[column]}`)
// 						break
// 					case "object":
// 						if (Array.isArray(filters[column])) {
// 							whereArr.push(
// 								`"${column}" IN (${
// 									typeof filters[column][0] === "string"
// 										? `'${filters[column].join("', '")}'`
// 										: `${filters[column].join(", ")}`
// 								})`
// 							)
// 						}
// 						break
// 					default:
// 						whereArr.push(`"${column}" = '${filters[column]}'`)
// 				}
// 			})
// 			query("BEGIN")
// 			let sql: string = `
//       		UPDATE "${this.TABLE_NAME}"
//       		SET "deletedAt" = 'NOW()'${
// 						deletedBy ? `, "deletedBy" = '${deletedBy}'` : ""
// 					}
//       		WHERE "deletedAt" IS NULL
// 			AND ${whereArr.join(" AND ")}
//       		`
// 			const {rows} = await query(sql)
// 			query("COMMIT")
// 			release()
// 			return rows
// 		} catch (error) {
// 			query("ROLLBACK")
// 			release()
// 			throw error
// 		}
// 	}
// }
