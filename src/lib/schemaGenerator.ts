import schemas from "../schemas/schemas.json"
import {resolve, join} from "path"
import * as TJS from "typescript-json-schema"
import fs from "fs"
import path from "path"
import crypto from "crypto"
import eventEmitter from "../lib/logging"

export default {
	generateSchema
}

const cacheBasePath = join(__dirname, "../../schema/cache.json")
let cacheBasedSchema = {}

const generateCacheBasedSchema = async (filePath: string) => {
	const content = fs.readFileSync(resolve(filePath))

	return crypto.createHash("sha1").update(content).digest("hex")
}

export async function generateSchema() {
	const schemaArr: any = {}

	// Manipulate Cache Schemas
	if (fs.existsSync(cacheBasePath)) {
		const fileContent = fs.readFileSync(cacheBasePath).toString()
		cacheBasedSchema = JSON.parse(fileContent)
	} else {
		fs.mkdirSync(cacheBasePath, {recursive: true})
		const fileContent = JSON.stringify(cacheBasedSchema, null, 2)
		fs.writeFileSync(cacheBasePath, fileContent)
	}

	for (let i = 0; i < schemas.length; i++) {
		const schemaPath: string = path.resolve(
			__dirname + `../../../src/${schemas[i].source}`
		)
		const hash: string = await generateCacheBasedSchema(schemaPath)

		if (
			cacheBasedSchema[`${schemas[i].basePath}`] &&
			cacheBasedSchema[`${schemas[i].basePath}`].hash === hash
		) {
			eventEmitter.emit(
				"logging",
				`using hash ${hash} for schemaPath ${schemaPath}`
			)
			schemaArr[`${schemas[i].basePath}`] =
				cacheBasedSchema[`${schemas[i].basePath}`]
			continue
		}

		eventEmitter.emit("logging", `started schemaPath ${schemaPath}`)

		// optionally pass argument to schema generator
		const settings: TJS.PartialArgs = {
			required: true,
			noExtraProps: true
		}

		// optionally pass ts compiler options
		const compilerOptions: TJS.CompilerOptions = {
			strictNullChecks: true
		}

		const program = TJS.getProgramFromFiles(
			[resolve(schemaPath)],
			compilerOptions
		)

		const generator = TJS.buildGenerator(program, settings)

		schemaArr[`${schemas[i].basePath}`] = {
			hash,
			schemas: {}
		}

		for (let k = 0; k < schemas[i].schemas.length; k++) {
			const source = {
				[`${schemas[i].schemas[k].apiPath}${schemas[i].schemas[k].method}`]: `${schemas[i].schemas[k].schema}`
			}
			let schema = {}

			if (generator) {
				schema = await Object.entries(source).reduce(
					(acc, [key, typeName]) => ({
						...acc,
						[key]: generator.getSchemaForSymbol(typeName)
					}),
					{}
				)
			}

			// special case for file upload
			if (schema) {
				Object.keys(schema).forEach((entry) => {
					if (
						schema[`${entry}`]["properties"] &&
						schema[`${entry}`]["properties"]["file"]
					) {
						schema[`${entry}`]["additionalProperties"] = true
					}
				})
			}

			const pathArr = Object.keys(schema)

			for (let j = 0; j < pathArr.length; j++) {
				// @ts-ignore
				// schemaArr.push(schema[pathArr[j]])
				schemaArr[`${schemas[i].basePath}`].schemas[
					`${schemas[i].schemas[k].apiPath}`
				] = schema[pathArr[j]]
			}
		}
		eventEmitter.emit("logging", `ended schemaPath ${schemaPath}`)
	}

	let schemaDirectory = cacheBasePath
	const content = JSON.stringify(schemaArr, null, 2)

	fs.writeFileSync(schemaDirectory, content)
	eventEmitter.emit("logging", "Schema generated")
}
