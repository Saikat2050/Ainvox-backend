import schemas from "../schemas/schemas.json"
import {resolve, join} from "path"
import * as TJS from "typescript-json-schema"
import fs from "fs"
import path from "path"

export default {
	generateSchema
}

export async function generateSchema() {
	const schemaArr: any = {}

	for (let i = 0; i < schemas.length; i++) {
		const schemaPath: string = path.resolve(
			__dirname + `./../${schemas[i].source}`
		)
		console.log(`started schemaPath`, schemaPath)

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
					// @ts-ignore
					if (schema[entry]["properties"]["file"]) {
						// @ts-ignore
						schema[entry]["additionalProperties"] = true
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
		console.log(`ended schemaPath`, schemaPath)
	}

	let schemaDirectory = join(__dirname, "../schema/cache.json")
	fs.existsSync(schemaDirectory) ||
		fs.mkdirSync(schemaDirectory, {recursive: true})
	const content = JSON.stringify(schemaArr, null, 2)

	fs.writeFileSync(schemaDirectory, content)
	if (process.env.DEBUG === "true") {
		console.log("Schema generated")
	}
}
