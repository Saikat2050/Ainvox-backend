export type OrderDir = 1 | -1

export type Range = Partial<{
	page: number
	pageSize: number
}>

export type Sort = Partial<{
	orderBy: string
	orderDir: OrderDir
}>

export type Timestamp = {
	createdAt: string
	updatedAt: string
	deletedAt: string
}

export type Error = {
	message: string
	status?: number
	code?: string
}

export type Headers = any & {
	userId: number
	roleId: number
}
