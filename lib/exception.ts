export class BCCError extends Error {
    code: number | Code

    constructor(code: number | Code, message: string) {
        super(message)
        this.code = code
        this.name = 'BCCError'
    }
}

export enum Code {
    /** Not an error, indicates success. */
    OK = 0,
    /** For any error that is not covered in the existing codes. */
    UNKNOWN,

    INVALID_ARGUMENT,
    PERMISSION_DENIED,
    /** For any error that was raised when making syscalls. */
    SYSTEM,
}

export function checkStatus(status: any) {
    if (status === null)
        return
    throw new BCCError(status.code, status.msg)
}
