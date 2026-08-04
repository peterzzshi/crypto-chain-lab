export const getElement = (id: string): HTMLElement | null => document.getElementById(id);

export const getElements = (selector: string): NodeListOf<Element> => document.querySelectorAll(selector);

export const getValue = (id: string): string => (getElement(id) as HTMLInputElement | HTMLTextAreaElement | null)?.value ?? '';

export const getTrimmedValue = (id: string): string => getValue(id).trim();

export const parseIntSafe = (value: string): number | null => {
    const parsed = parseInt(value, 10);
    return isNaN(parsed) ? null : parsed;
};

export const isNumericString = (str: string): boolean => /^\d+$/.test(str);

export interface ValidationSuccess {
    readonly valid: true;
}

export interface ValidationError {
    readonly valid: false;
    readonly error: string;
}

export type ValidationResult = ValidationSuccess | ValidationError;

const validationSuccess: ValidationSuccess = { valid: true } as const;

const validationError = (error: string): ValidationError => ({ valid: false, error }) as const;

export const validateNonEmpty = (value: string, fieldName: string): ValidationResult =>
    value ? validationSuccess : validationError(`Please enter ${fieldName}`);

export const validateNumbers = (...values: readonly (number | null)[]): ValidationResult =>
    values.every(v => v !== null)
        ? validationSuccess
        : validationError('Please enter valid prime numbers');

export interface ParsedResultOk<T> {
    readonly ok: true;
    readonly data: T;
}

export interface ParsedResultError {
    readonly ok: false;
    readonly error: string;
}

export type ParsedResult<T> = ParsedResultOk<T> | ParsedResultError;

export const parseResult = <T>(jsonString: string): ParsedResult<T> => {
    const result = JSON.parse(jsonString) as T & { success?: boolean; error?: string };
    return result.success || !result.error
        ? { ok: true, data: result } as const
        : { ok: false, error: result.error } as const;
};

const createEnterKeyHandler = (requireNoShift: boolean) =>
    (handler: () => void) =>
    (e: KeyboardEvent): void => {
        if (e.key === 'Enter' && (!requireNoShift || !e.shiftKey)) {
            e.preventDefault();
            handler();
        }
    };

export const onEnterKey = createEnterKeyHandler(false);

export const onEnterKeyUnlessShift = createEnterKeyHandler(true);

