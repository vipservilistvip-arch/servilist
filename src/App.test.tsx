import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import App from './App'

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
}

Object.defineProperty(window, 'localStorage', {
  value: mockLocalStorage,
})

describe('App component', () => {
  beforeEach(() => {
    // Clear mocks before each test
    vi.clearAllMocks()
  })

  it('renders the main title', () => {
    render(<App />)
    expect(screen.getByText(/ServList/i)).toBeInTheDocument()
  })

  it('renders server list with mock data', () => {
    render(<App />)
    
    // Check if server names are in the document
    expect(screen.getByText('SRV-DB-PROD')).toBeInTheDocument()
    expect(screen.getByText('SRV-APP-WEB')).toBeInTheDocument()
    
    // Check if client names are in the document
    expect(screen.getByText('Posto Central')).toBeInTheDocument()
    expect(screen.getByText('Mercado Silva')).toBeInTheDocument()
    
    // Check if IP addresses with ports are in the document
    expect(screen.getByText('10.0.0.15:3306')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.50:80')).toBeInTheDocument()
  })

  it('opens and closes the add server modal', () => {
    render(<App />)
    
    // Click add server button
    fireEvent.click(screen.getByText('Novo Servidor'))
    
    // Check if modal is open
    expect(screen.getByText('Cadastrar Novo Servidor')).toBeInTheDocument()
    
    // Click cancel button
    fireEvent.click(screen.getByText('Cancelar'))
    
    // Check if modal is closed
    expect(screen.queryByText('Cadastrar Novo Servidor')).not.toBeInTheDocument()
  })

  it('adds a new server', () => {
    render(<App />)
    
    // Click add server button
    fireEvent.click(screen.getByText('Novo Servidor'))
    
    // Fill in the form
    fireEvent.change(screen.getByPlaceholderText(/Ex: SRV-APP-01/i), {
      target: { value: 'SRV-TEST-01' }
    })
    fireEvent.change(screen.getByPlaceholderText(/Ex: Loja Modelo/i), {
      target: { value: 'Empresa Teste' }
    })
    fireEvent.change(screen.getByPlaceholderText(/192.168.x.x/i), {
      target: { value: '192.168.1.100' }
    })
    fireEvent.change(screen.getByPlaceholderText(/80/i), {
      target: { value: '443' }
    })
    fireEvent.change(screen.getByPlaceholderText(/api\.cliente\.local/i), {
      target: { value: 'api.empresa-teste.local' }
    })
    fireEvent.change(screen.getByPlaceholderText(/Ex: Sala TI - fundos/i), {
      target: { value: 'Unidade Centro - Sala TI' }
    })
    fireEvent.change(screen.getByPlaceholderText(/^admin$/i), {
      target: { value: 'mk-user-teste' }
    })
    fireEvent.change(screen.getByPlaceholderText(/^\*{6}$/), {
      target: { value: 'senha123' }
    })
    
    // Click save button
    fireEvent.click(screen.getByText('Salvar Servidor'))
    
    // Check if the new server is added
    expect(screen.getByText('SRV-TEST-01')).toBeInTheDocument()
    expect(screen.getByText('Empresa Teste')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.100:443')).toBeInTheDocument()
    expect(screen.getByText('api.empresa-teste.local')).toBeInTheDocument()
    expect(screen.getByText(/Unidade Centro - Sala TI/i)).toBeInTheDocument()
    expect(screen.getByText(/MikroTik: mk-user-teste/i)).toBeInTheDocument()
    expect(screen.getAllByText('Senha: ********').length).toBeGreaterThan(0)
  })

  it('searches for servers', () => {
    render(<App />)
    
    // Type in search box
    fireEvent.change(screen.getByPlaceholderText(/Buscar servidor, cliente ou IP/i), {
      target: { value: 'DB' }
    })
    
    // Check if only matching server is visible
    expect(screen.getByText('SRV-DB-PROD')).toBeInTheDocument()
    expect(screen.queryByText('SRV-APP-WEB')).not.toBeInTheDocument()
  })

  it('displays statistics correctly', () => {
    render(<App />)
    
    // Check total servers
    expect(screen.getByText('Total de Servidores')).toBeInTheDocument()
    
    // Check online servers
    expect(screen.getByText('Online')).toBeInTheDocument()
    
    // Check backup success count
    expect(screen.getByText('Backups em Dia')).toBeInTheDocument()
    
    // Check backup failure count
    expect(screen.getByText('Falhas de Backup')).toBeInTheDocument()
  })

  it('calls localStorage on initial load', () => {
    render(<App />)
    
    // Verify localStorage.getItem is called
    expect(mockLocalStorage.getItem).toHaveBeenCalledWith('servlist_servers')
  })

  it('calls ping function when checking connectivity', () => {
    render(<App />)
    
    // Click check connectivity button
    fireEvent.click(screen.getByText('Verificar Conexão'))
    
    // Check if button shows loading state
    expect(screen.getByText('Verificando...')).toBeInTheDocument()
  })

  it('edits an existing server', () => {
    render(<App />)
    
    // Find and click the first edit button in the server table
    const editButtons = screen.getAllByLabelText('Editar servidor')
    fireEvent.click(editButtons[0])
    
    // Check if edit modal is open
    expect(screen.getByText('Editar Servidor')).toBeInTheDocument()
    
    // Change the server name and port
    fireEvent.change(screen.getByPlaceholderText(/Ex: SRV-APP-01/i), {
      target: { value: 'SRV-DB-PROD-UPDATED' }
    })
    fireEvent.change(screen.getByPlaceholderText(/80/i), {
      target: { value: '3307' }
    })
    fireEvent.change(screen.getByPlaceholderText(/api\.cliente\.local/i), {
      target: { value: 'db-interno.cliente.local' }
    })
    fireEvent.change(screen.getByPlaceholderText(/^admin$/i), {
      target: { value: 'mk-admin-db' }
    })
    fireEvent.change(screen.getByPlaceholderText(/^\*{6}$/), {
      target: { value: 'dbsenha' }
    })
    
    // Click update button
    fireEvent.click(screen.getByText('Atualizar Servidor'))
    
    // Check if the server name and port were updated
    expect(screen.getByText('SRV-DB-PROD-UPDATED')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.15:3307')).toBeInTheDocument()
    expect(screen.getByText('db-interno.cliente.local')).toBeInTheDocument()
    expect(screen.getByText(/MikroTik: mk-admin-db/i)).toBeInTheDocument()
    expect(screen.getAllByText('Senha: *******').length).toBeGreaterThan(0)
  })
})
