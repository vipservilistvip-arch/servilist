import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import App from './App'

const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
}

Object.defineProperty(window, 'localStorage', {
  value: mockLocalStorage,
})

describe('App auth flow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockLocalStorage.getItem.mockReturnValue(null)
  })

  it('renders login when no active session exists', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ user: null }),
      })
    )

    render(<App />)

    expect(await screen.findByText('Entrar no ServList')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Entrar' })).toBeInTheDocument()
  })

  it('renders dashboard when session exists', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          user: {
            id: 1,
            name: 'Admin',
            email: 'admin@test.com',
            createdAt: '2026-02-12T10:00:00Z',
          },
        }),
      })
    )

    render(<App />)

    expect(await screen.findByText(/ServList/i)).toBeInTheDocument()
    expect(screen.getByText('Novo Servidor')).toBeInTheDocument()
  })

  it('logs out and goes back to login screen', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: {
            id: 1,
            name: 'Admin',
            email: 'admin@test.com',
            createdAt: '2026-02-12T10:00:00Z',
          },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ ok: true }),
      })

    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByText('Novo Servidor')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Sair' }))

    await waitFor(() => {
      expect(screen.getByText('Entrar no ServList')).toBeInTheDocument()
    })
  })
})
