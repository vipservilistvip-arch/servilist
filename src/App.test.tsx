import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import App from './App'

const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
}

const sessionUser = {
  id: 1,
  name: 'Admin',
  email: 'admin@test.com',
  createdAt: '2026-02-12T10:00:00Z',
}

const mockServer = {
  id: 'srv-1',
  name: 'SRV-APP-01',
  client: 'Loja Modelo',
  ip: '192.168.0.10',
  port: '443',
  endpoint: 'api.loja-modelo.local',
  referencePoint: 'Sala TI',
  mikrotikUser: 'admin',
  mikrotikPassword: 'segredo',
  os: 'Ubuntu 24.04',
  hardware: '4 vCPU / 16 GB RAM',
  status: 'online' as const,
  backupStatus: 'success' as const,
  lastBackup: '2026-03-06 22:00',
  notes: 'Servidor principal',
}

const mockContract = {
  id: 'ctr-1',
  name: 'Link Matriz',
  equipmentUser: 'provedor-admin',
  equipmentPassword: 'senha-pppoe',
  providerName: 'Provedor X',
  providerContact: '(11) 99999-0000',
  providerHolder: 'Empresa Modelo LTDA',
  providerCpfCnpj: '12.345.678/0001-99',
  providerCity: 'Sao Paulo - SP',
  notes: 'Contrato principal da matriz',
}

function jsonResponse(payload: unknown) {
  return {
    ok: true,
    json: async () => payload,
  }
}

function setupFetch(user: typeof sessionUser | null) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)

    if (url.includes('/api/auth/me')) {
      return Promise.resolve(jsonResponse({ user }))
    }

    if (url.includes('/api/servers')) {
      return Promise.resolve(jsonResponse({ servers: user ? [mockServer] : [] }))
    }

    if (url.includes('/api/contract-points')) {
      return Promise.resolve(jsonResponse({ contractPoints: user ? [mockContract] : [] }))
    }

    if (url.includes('/api/auth/logout')) {
      return Promise.resolve(jsonResponse({ ok: true }))
    }

    return Promise.resolve(jsonResponse({}))
  })
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
    vi.stubGlobal('fetch', setupFetch(null))

    render(<App />)

    expect(await screen.findByText('Entrar no ServList')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Entrar' })).toBeInTheDocument()
  })

  it('renders dashboard when session exists', async () => {
    vi.stubGlobal('fetch', setupFetch(sessionUser))

    render(<App />)

    expect(await screen.findByText(/ServList/i)).toBeInTheDocument()
    expect(await screen.findByText('Novo Servidor')).toBeInTheDocument()
    expect(await screen.findByText('SRV-APP-01')).toBeInTheDocument()
  })

  it('opens the details tab for a server', async () => {
    vi.stubGlobal('fetch', setupFetch(sessionUser))

    render(<App />)

    expect(await screen.findByText('SRV-APP-01')).toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('Ver detalhes do servidor'))

    expect(await screen.findByText('Servidor cadastrado')).toBeInTheDocument()
    expect(screen.getByText('Cliente: Loja Modelo')).toBeInTheDocument()
    expect(screen.getByText('Sala TI')).toBeInTheDocument()
    expect(screen.getByText('Ubuntu 24.04')).toBeInTheDocument()
  })

  it('opens the details tab for a contract point', async () => {
    vi.stubGlobal('fetch', setupFetch(sessionUser))

    render(<App />)

    expect(await screen.findByText('Novo Servidor')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Pontos de Contrata/i }))
    expect(await screen.findByText('Link Matriz')).toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('Ver detalhes do ponto'))

    expect(await screen.findByText('Ponto cadastrado')).toBeInTheDocument()
    expect(screen.getByText('Fornecedor: Provedor X')).toBeInTheDocument()
    expect(screen.getByText('Empresa Modelo LTDA')).toBeInTheDocument()
    expect(screen.getByText('Sao Paulo - SP')).toBeInTheDocument()
  })

  it('logs out and goes back to login screen', async () => {
    const fetchMock = setupFetch(sessionUser)
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByText('Novo Servidor')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Sair' }))

    await waitFor(() => {
      expect(screen.getByText('Entrar no ServList')).toBeInTheDocument()
    })
  })
})
