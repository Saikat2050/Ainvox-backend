import MySql from "mysql"

export class DBHelper {
	private pool: MySql.Pool
	public constructor() {
		const connectionLimit: number = Number(
			process.env.CONNECTION_LIMIT || 10
		)

		this.pool = MySql.createPool({
			host: process.env.DB_HOST,
			database: process.env.DB_NAME,
			user: process.env.DB_USER,
			password: process.env.DB_PASSWORD,
			port: Number(process.env.DB_PORT || 3306),
			charset: "utf8mb4",
			connectionLimit
		})
	}

	public getConnection(): Promise<MySql.PoolConnection> {
		return new Promise((resolve, reject) => {
			this.pool.getConnection((err, connection: MySql.PoolConnection) => {
				if (err) {
					reject(err)
				} else {
					resolve(connection)
				}
			})
		})
	}

	public rawQuery(
		conn: MySql.PoolConnection,
		sql: string,
		values: any[]
	): Promise<any> {
		return new Promise((resolve, reject) => {
			if (process.env.LOG_SQL === "true") {
				console.log("-------- SQL=")
				const fullSql = conn.format(sql, values)
				console.log(fullSql)
				console.log("--------")
			}

			conn.query(sql, values, (err, result) => {
				if (err) {
					reject(err)
				} else {
					resolve(result)
				}
			})
		})
	}

	public async query(sql: string, values: any[] = []): Promise<any> {
		if (!sql) {
			return []
		}
		const conn = await this.getConnection()
		try {
			await this.rawQuery(conn, process.env.DB_NAME as string, [])

			return await this.rawQuery(conn, sql, values)
		} catch (e: any) {
			throw e
		} finally {
			conn.release()
		}
	}
}
