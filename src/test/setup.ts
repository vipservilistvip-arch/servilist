import '@testing-library/jest-dom'
import { expect, afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// Extend Vitest's expect method with methods from testing-library/jest-dom
expect.extend({
  toBeInTheDocument: (element: any) => {
    return {
      pass: !!element,
      message: () => 'Element is not in the document'
    }
  },
  toHaveTextContent: (element: any, text: string) => {
    if (!element) {
      return { pass: false, message: () => 'Element is null or undefined' }
    }
    const elementText = element.textContent || ''
    const pass = elementText.includes(text)
    return {
      pass,
      message: () => `Expected element to contain "${text}", but got "${elementText}"`
    }
  }
})

// Cleanup after each test case
afterEach(() => {
  cleanup()
})