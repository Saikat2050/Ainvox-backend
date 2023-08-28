import {Postgrator} from "postgrator"
import {MySQLOptions} from "postgrator"

export class Migrator {
    public static async migrateDB(migrationDirectory: string): Promise<void> {
        const username: string = process.env.DB_USER as string
        const password: string = process.env.DB_PASSWORD as string

        const postgratorOptions: MySQLOptions = {
            migrationDirectory,
            driver: "mysql",
            validateChecksums: true,
            host: process.env.DB_HOST,
            port: Number(process.env.DB_PORT || 3306),
            username,
            password,
            database: process.env.DB_NAME
        }

        const postgrator = new Postgrator(postgratorOptions)

        try {
            console.log(`Migration Started`)
            let r = await postgrator.migrate()
            console.log(`Migration Completed`)
            console.log(r)
        } catch (e: any) {
            console.log(`Migration Failed`)
            console.log(e)
            throw e
        }
    }
}