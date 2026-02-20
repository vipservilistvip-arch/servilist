import { useState, useEffect } from 'react'
import { 
  Server, 
  Search, 
  Plus, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  Database, 
  HardDrive, 
  User, 
  Globe, 
  Trash2,
  Edit2,
  Wifi,
  WifiOff,
  UserPlus,
  FileText,
  Settings,
  Download,
  Upload
} from 'lucide-react'

interface ServerData {
  id: string
  name: string
  client: string
  ip: string
  port: string
  endpoint: string
  referencePoint: string
  mikrotikUser: string
  mikrotikPassword: string
  os: string
  hardware: string
  status: 'online' | 'offline' | 'maintenance'
  backupStatus: 'success' | 'failed' | 'pending'
  lastBackup: string
  notes: string
}

interface ContractPoint {
  id: string
  name: string
  equipmentUser: string
  equipmentPassword: string
  providerName: string
  providerContact: string
  providerHolder: string
  providerCpfCnpj: string
  providerCity: string
  notes: string
}

interface PingStatus {
  isOnline: boolean
  latency: number // in milliseconds
  lastCheck: string
  downtimeStart?: string
}

interface PingDashboardEntry {
  serverId: string
  name: string
  client: string
  endpoint: string
  ping: PingStatus
}

interface AuthUser {
  id: number
  name: string
  email: string
  createdAt: string
}

interface BackupSettings {
  smtpServer: string
  smtpPort: string
  smtpUser: string
  smtpPassword?: string
  backupEmail: string
}

type AuthMode = 'login' | 'register'

const PING_TIMEOUT_MS = 1500
const PING_ATTEMPTS = 3
const API_BASE_URL = import.meta.env.VITE_API_URL || ''

function normalizeProbeUrl(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url
}

function buildProbeTargets(ip: string, port: string): string[] {
  const trimmedIp = ip.trim()
  if (!trimmedIp) return []

  if (trimmedIp.startsWith('http://') || trimmedIp.startsWith('https://')) {
    return [normalizeProbeUrl(trimmedIp)]
  }

  const sanitizedPort = (port || '').trim()
  const portSuffix = sanitizedPort ? `:${sanitizedPort}` : ''

  // Prefer HTTPS first and fallback to HTTP.
  return [
    normalizeProbeUrl(`https://${trimmedIp}${portSuffix}`),
    normalizeProbeUrl(`http://${trimmedIp}${portSuffix}`)
  ]
}

async function probeLatency(targetUrl: string, timeoutMs: number): Promise<number | null> {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs)
  const startedAt = performance.now()

  try {
    await fetch(`${targetUrl}/favicon.ico?t=${Date.now()}`, {
      method: 'GET',
      mode: 'no-cors',
      cache: 'no-store',
      signal: controller.signal
    })
    return Math.round(performance.now() - startedAt)
  } catch {
    return null
  } finally {
    window.clearTimeout(timeoutId)
  }
}

function getMedianLatency(latencies: number[]): number {
  const sorted = [...latencies].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)

  if (sorted.length % 2 === 0) {
    return Math.round((sorted[middle - 1] + sorted[middle]) / 2)
  }

  return sorted[middle]
}

// HTTP-based latency check with multiple samples for more stable ms values.
async function pingServer(ip: string, port: string): Promise<PingStatus> {
  const probeTargets = buildProbeTargets(ip, port)
  if (probeTargets.length === 0) {
    return {
      isOnline: false,
      latency: PING_TIMEOUT_MS,
      lastCheck: new Date().toISOString()
    }
  }

  const samples: number[] = []

  for (let attempt = 0; attempt < PING_ATTEMPTS; attempt += 1) {
    let sample: number | null = null

    for (const target of probeTargets) {
      sample = await probeLatency(target, PING_TIMEOUT_MS)
      if (sample !== null) {
        break
      }
    }

    if (sample !== null) {
      samples.push(sample)
    }
  }

  const latency = samples.length > 0 ? getMedianLatency(samples) : PING_TIMEOUT_MS

  return {
    isOnline: samples.length > 0,
    latency,
    lastCheck: new Date().toISOString()
  }
}

function App() {
  const [servers, setServers] = useState<ServerData[]>([])
  
  const [searchTerm, setSearchTerm] = useState('')
  const [isAddingServer, setIsAddingServer] = useState(false)
  const [isEditingServer, setIsEditingServer] = useState(false)
  const [newServer, setNewServer] = useState<Partial<ServerData>>({
    status: 'online',
    backupStatus: 'pending',
    port: '80',
    endpoint: '',
    referencePoint: '',
    mikrotikUser: '',
    mikrotikPassword: ''
  })
  const [editingServer, setEditingServer] = useState<ServerData | null>(null)
  const [isRegisteringUser, setIsRegisteringUser] = useState(false)
  const [pingStatus, setPingStatus] = useState<{ [key: string]: PingStatus }>({})
  const [isPinging, setIsPinging] = useState(false)
  const [autoPingEnabled, setAutoPingEnabled] = useState(false)
  const [authUser, setAuthUser] = useState<AuthUser | null>(null)
  const [authLoading, setAuthLoading] = useState(true)
  const [authMode, setAuthMode] = useState<AuthMode>('login')
  const [authError, setAuthError] = useState('')
  const [authSubmitting, setAuthSubmitting] = useState(false)
  const [serversLoading, setServersLoading] = useState(false)
  const [serversError, setServersError] = useState('')
  const [authForm, setAuthForm] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
  })

  const [activeTab, setActiveTab] = useState<'servers' | 'contracts' | 'settings'>('servers')
  const [backupSettings, setBackupSettings] = useState<BackupSettings>({
    smtpServer: '',
    smtpPort: '587',
    smtpUser: '',
    backupEmail: ''
  })
  const [settingsLoading, setSettingsLoading] = useState(false)
  const [contractPoints, setContractPoints] = useState<ContractPoint[]>([])
  const [isAddingContract, setIsAddingContract] = useState(false)
  const [isEditingContract, setIsEditingContract] = useState(false)
  const [newContract, setNewContract] = useState<Partial<ContractPoint>>({})
  const [editingContract, setEditingContract] = useState<ContractPoint | null>(null)
  const [contractsLoading, setContractsLoading] = useState(false)
  const [contractsError, setContractsError] = useState('')

  const authCardTitle = authMode === 'login' ? 'Entrar no ServList' : 'Criar conta'

  const apiFetch = async <T,>(path: string, options: RequestInit = {}): Promise<T> => {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    })

    const payload = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new Error(payload.error || 'Erro inesperado.')
    }
    return payload as T
  }

  useEffect(() => {
    let mounted = true

    const loadCurrentUser = async () => {
      try {
        const data = await apiFetch<{ user: AuthUser | null }>('/api/auth/me', { method: 'GET' })
        if (mounted) {
          setAuthUser(data.user)
        }
      } catch {
        if (mounted) {
          setAuthUser(null)
        }
      } finally {
        if (mounted) {
          setAuthLoading(false)
        }
      }
    }

    loadCurrentUser()
    return () => {
      mounted = false
    }
  }, [])

  const loadServers = async () => {
    setServersLoading(true)
    setServersError('')
    try {
      const data = await apiFetch<{ servers: ServerData[] }>('/api/servers', { method: 'GET' })
      setServers(data.servers)
      setPingStatus({})
    } catch (error) {
      setServersError(error instanceof Error ? error.message : 'Falha ao carregar servidores.')
      setServers([])
    } finally {
      setServersLoading(false)
    }
  }

  const loadContractPoints = async () => {
    setContractsLoading(true)
    setContractsError('')
    try {
      const data = await apiFetch<{ contractPoints: ContractPoint[] }>('/api/contract-points', { method: 'GET' })
      setContractPoints(data.contractPoints)
    } catch (error) {
      setContractsError(error instanceof Error ? error.message : 'Falha ao carregar pontos de contratação.')
      setContractPoints([])
    } finally {
      setContractsLoading(false)
    }
  }

  useEffect(() => {
    if (!authUser) {
      setServers([])
      setContractPoints([])
      setPingStatus({})
      return
    }
    loadServers()
    loadContractPoints()
  }, [authUser])

  // Auto ping functionality every minute
  useEffect(() => {
    let intervalId: number | null = null
    
    if (autoPingEnabled) {
      // Initial check
      checkAllConnectivity()
      
      // Schedule checks every minute (60000ms)
      intervalId = window.setInterval(() => {
        checkAllConnectivity()
      }, 60000)
    }
    
    return () => {
      if (intervalId) {
        window.clearInterval(intervalId)
      }
    }
  }, [autoPingEnabled, servers])

  // Handle ESC key to close modal
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && isAddingServer) {
        setIsAddingServer(false)
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [isAddingServer])

  const resetServerForm = () => {
    setNewServer({ status: 'online', backupStatus: 'pending', port: '80', endpoint: '', referencePoint: '', mikrotikUser: '', mikrotikPassword: '' })
  }

  const handleAddServer = async () => {
    if (newServer.name && newServer.client) {
      const server: ServerData = {
        id: crypto.randomUUID(),
        name: newServer.name as string,
        client: newServer.client as string,
        ip: newServer.ip || 'N/A',
        port: newServer.port || '80',
        endpoint: newServer.endpoint || 'N/A',
        referencePoint: newServer.referencePoint || '',
        mikrotikUser: newServer.mikrotikUser || '',
        mikrotikPassword: newServer.mikrotikPassword || '',
        os: newServer.os || 'N/A',
        hardware: newServer.hardware || 'N/A',
        status: newServer.status || 'online',
        backupStatus: newServer.backupStatus || 'pending',
        lastBackup: new Date().toLocaleString(),
        notes: newServer.notes || ''
      }
      try {
        const data = await apiFetch<{ server: ServerData }>('/api/servers', {
          method: 'POST',
          body: JSON.stringify(server),
        })
        setServers([data.server, ...servers])
      } catch (error) {
        setServersError(error instanceof Error ? error.message : 'Falha ao cadastrar servidor.')
        return
      }
      setIsAddingServer(false)
      resetServerForm()
    }
  }

  const handleEditServer = async () => {
    if (editingServer && newServer.name && newServer.client) {
      const payload: ServerData = {
        ...editingServer,
        name: newServer.name as string,
        client: newServer.client as string,
        ip: newServer.ip || 'N/A',
        port: newServer.port || '80',
        endpoint: newServer.endpoint || 'N/A',
        referencePoint: newServer.referencePoint || '',
        mikrotikUser: newServer.mikrotikUser || '',
        mikrotikPassword: newServer.mikrotikPassword || '',
        os: newServer.os || 'N/A',
        hardware: newServer.hardware || 'N/A',
        status: newServer.status || 'online',
        backupStatus: newServer.backupStatus || 'pending',
        notes: newServer.notes || '',
      }

      try {
        const data = await apiFetch<{ server: ServerData }>(`/api/servers/${editingServer.id}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        })
        setServers(servers.map((server) => (server.id === editingServer.id ? data.server : server)))
      } catch (error) {
        setServersError(error instanceof Error ? error.message : 'Falha ao atualizar servidor.')
        return
      }

      setIsEditingServer(false)
      setEditingServer(null)
      resetServerForm()
    }
  }

  const startEditServer = (server: ServerData) => {
    setEditingServer(server)
    setNewServer({
      name: server.name,
      client: server.client,
      ip: server.ip,
      port: server.port,
      endpoint: server.endpoint,
      referencePoint: server.referencePoint,
      mikrotikUser: server.mikrotikUser,
      mikrotikPassword: server.mikrotikPassword,
      os: server.os,
      hardware: server.hardware,
      status: server.status,
      backupStatus: server.backupStatus,
      notes: server.notes
    })
    setIsEditingServer(true)
  }

  // Check connectivity for all servers
  const checkAllConnectivity = async () => {
    setIsPinging(true)
    const status: { [key: string]: PingStatus } = {}

    const results = await Promise.all(
      servers.map(async (server) => {
        const connectivityTarget = (server.endpoint && server.endpoint !== 'N/A')
          ? server.endpoint
          : server.ip

        if (!connectivityTarget || connectivityTarget === 'N/A') {
          return null
        }

        const result = await pingServer(connectivityTarget, server.port)
        return { server, result }
      })
    )

    for (const item of results) {
      if (!item) continue
      const { server, result } = item

      // Check if server was previously online/offline to track downtime
      const previousStatus = pingStatus[server.id]
      if (!result.isOnline && previousStatus?.isOnline) {
        result.downtimeStart = new Date().toISOString()
      } else if (result.isOnline && !previousStatus?.isOnline && previousStatus?.downtimeStart) {
        // Server is back online, clear downtime start
        delete result.downtimeStart
      } else if (!result.isOnline && previousStatus?.downtimeStart) {
        // Server is still offline, keep existing downtime start
        result.downtimeStart = previousStatus.downtimeStart
      }

      status[server.id] = result
    }

    setPingStatus(status)
    setIsPinging(false)
  }

  // Calculate downtime duration in minutes:seconds format
  const calculateDowntime = (downtimeStart: string): string => {
    const start = new Date(downtimeStart)
    const now = new Date()
    const diff = now.getTime() - start.getTime()
    
    const minutes = Math.floor(diff / 60000)
    const seconds = Math.floor((diff % 60000) / 1000)
    
    return `${minutes}m ${seconds}s`
  }

  const deleteServer = async (id: string) => {
    try {
      await apiFetch(`/api/servers/${id}`, { method: 'DELETE' })
      setServers(servers.filter((server) => server.id !== id))
    } catch (error) {
      setServersError(error instanceof Error ? error.message : 'Falha ao excluir servidor.')
    }
  }

  const filteredServers = servers.filter(s => 
    s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.client.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.ip.includes(searchTerm) ||
    (s.endpoint || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (s.referencePoint || '').toLowerCase().includes(searchTerm.toLowerCase())
  )

  const pingDashboardEntries: PingDashboardEntry[] = filteredServers
    .map((server) => {
      const ping = pingStatus[server.id]
      if (!ping) return null

      return {
        serverId: server.id,
        name: server.name,
        client: server.client,
        endpoint: (server.endpoint && server.endpoint !== 'N/A')
          ? server.endpoint
          : `${server.ip}:${server.port}`,
        ping
      }
    })
    .filter((entry): entry is PingDashboardEntry => entry !== null)
    .sort((a, b) => {
      if (a.ping.isOnline !== b.ping.isOnline) {
        return a.ping.isOnline ? -1 : 1
      }
      return a.ping.latency - b.ping.latency
    })

  const onlineEntries = pingDashboardEntries.filter(entry => entry.ping.isOnline)
  const onlineLatencies = onlineEntries.map(entry => entry.ping.latency)
  const averageLatency = onlineLatencies.length > 0
    ? Math.round(onlineLatencies.reduce((sum, value) => sum + value, 0) / onlineLatencies.length)
    : 0
  const minLatency = onlineLatencies.length > 0 ? Math.min(...onlineLatencies) : 0
  const maxLatency = onlineLatencies.length > 0 ? Math.max(...onlineLatencies) : 0
  const criticalLatencyCount = onlineLatencies.filter(value => value >= 150).length

  const getLatencyBadgeClass = (latency: number): string => {
    if (latency < 60) return 'bg-emerald-100 text-emerald-700'
    if (latency < 120) return 'bg-amber-100 text-amber-700'
    return 'bg-rose-100 text-rose-700'
  }

  const resetAuthForm = () => {
    setAuthForm({
      name: '',
      email: '',
      password: '',
      confirmPassword: '',
    })
  }

  const handleAuthSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setAuthError('')

    if (!authForm.email || !authForm.password) {
      setAuthError('Email e senha sao obrigatorios.')
      return
    }

    if (authMode === 'register') {
      if (!authForm.name.trim()) {
        setAuthError('Informe o nome para cadastro.')
        return
      }
      if (authForm.password !== authForm.confirmPassword) {
        setAuthError('As senhas nao conferem.')
        return
      }
    }

    setAuthSubmitting(true)
    try {
      const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register'
      const payload = authMode === 'login'
        ? {
            email: authForm.email,
            password: authForm.password,
          }
        : {
            name: authForm.name.trim(),
            email: authForm.email,
            password: authForm.password,
          }

      const data = await apiFetch<{ user: AuthUser }>(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload),
      })

      setAuthUser(data.user)
      resetAuthForm()
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'Falha de autenticacao.')
    } finally {
      setAuthSubmitting(false)
    }
  }

  const handleInternalRegister = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setAuthError('')

    if (!authForm.name.trim() || !authForm.email || !authForm.password) {
      setAuthError('Todos os campos sao obrigatorios.')
      return
    }

    if (authForm.password !== authForm.confirmPassword) {
      setAuthError('As senhas nao conferem.')
      return
    }

    setAuthSubmitting(true)
    try {
      await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          name: authForm.name.trim(),
          email: authForm.email,
          password: authForm.password,
        }),
      })

      // Como o backend faz login automatico ao registrar, precisamos recarregar o usuario
      // para garantir que a sessao ainda e valida ou refletir a mudanca se desejado.
      // No entanto, para "criar um usuario para outro", o ideal seria um endpoint admin.
      // Por enquanto, apenas fechamos o modal e limpamos o formulário.
      setIsRegisteringUser(false)
      resetAuthForm()
      alert('Usuário cadastrado com sucesso!')
      
      // Opcional: Recarregar a página para garantir que a sessão do admin não foi perdida
      // (embora o backend atual limpe a sessão ao registrar novo usuário).
      window.location.reload()
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'Falha ao cadastrar usuário.')
    } finally {
      setAuthSubmitting(false)
    }
  }

  const handleAddContract = async () => {
    if (newContract.name) {
      const contract: Partial<ContractPoint> = {
        ...newContract,
        id: crypto.randomUUID()
      }

      try {
        const data = await apiFetch<{ contractPoint: ContractPoint }>('/api/contract-points', {
          method: 'POST',
          body: JSON.stringify(contract)
        })

        setContractPoints([data.contractPoint, ...contractPoints])
        setNewContract({})
        setIsAddingContract(false)
      } catch (error) {
        alert(error instanceof Error ? error.message : 'Falha ao criar ponto de contratação.')
      }
    }
  }

  const handleUpdateContract = async () => {
    if (editingContract && newContract.name) {
      try {
        const data = await apiFetch<{ contractPoint: ContractPoint }>(`/api/contract-points/${editingContract.id}`, {
          method: 'PUT',
          body: JSON.stringify(newContract)
        })

        setContractPoints(contractPoints.map(c => (c.id === editingContract.id ? data.contractPoint : c)))
        setEditingContract(null)
        setNewContract({})
        setIsEditingContract(false)
      } catch (error) {
        alert(error instanceof Error ? error.message : 'Falha ao atualizar ponto de contratação.')
      }
    }
  }

  const handleDeleteContract = async (id: string) => {
    if (confirm('Tem certeza que deseja excluir este ponto de contratação?')) {
      try {
        await apiFetch<{ ok: boolean }>(`/api/contract-points/${id}`, { method: 'DELETE' })
        setContractPoints(contractPoints.filter(c => c.id !== id))
      } catch (error) {
        alert(error instanceof Error ? error.message : 'Falha ao excluir ponto de contratação.')
      }
    }
  }

  const loadSettings = async () => {
    try {
      setSettingsLoading(true)
      const data = await apiFetch<{ settings: BackupSettings }>('/api/settings/backup')
      setBackupSettings(data.settings)
    } catch (error) {
      console.error('Failed to load settings', error)
    } finally {
      setSettingsLoading(false)
    }
  }

  useEffect(() => {
    if (activeTab === 'settings' && authUser) {
      loadSettings()
    }
  }, [activeTab, authUser])

  const handleSaveSettings = async () => {
    try {
      await apiFetch('/api/settings/backup', {
        method: 'POST',
        body: JSON.stringify(backupSettings)
      })
      alert('Configurações salvas com sucesso!')
    } catch (error) {
      alert('Erro ao salvar configurações.')
    }
  }

  const handleTestBackup = async () => {
    try {
      const data = await apiFetch<{ message: string }>('/api/backup/test', { method: 'POST' })
      alert(data.message)
    } catch (error) {
      alert('Erro ao testar backup: ' + (error instanceof Error ? error.message : 'Unknown error'))
    }
  }

  const handleDownloadBackup = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/backup/download`, {
        method: 'GET',
        credentials: 'include',
      })
      
      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        const contentDisposition = response.headers.get('Content-Disposition')
        let filename = `servlist_backup_${new Date().toISOString().slice(0,10)}.db`
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/)
            if (filenameMatch && filenameMatch.length === 2)
                filename = filenameMatch[1]
        }
        
        a.download = filename
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        a.remove()
      } else {
        if (response.status === 401) {
            handleLogout()
            return
        }
        alert('Erro ao baixar backup')
      }
    } catch (error) {
      console.error('Error downloading backup:', error)
      alert('Erro ao baixar backup')
    }
  }

  const handleRestoreBackup = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    if (!confirm('ATENÇÃO: Restaurar um backup substituirá todos os dados atuais do sistema. Uma cópia de segurança dos dados atuais será criada automaticamente antes da substituição.\n\nDeseja continuar?')) {
      event.target.value = ''
      return
    }

    const formData = new FormData()
    formData.append('file', file)

    try {
      setSettingsLoading(true)
      const response = await fetch(`${API_BASE_URL}/api/backup/restore`, {
        method: 'POST',
        body: formData,
        credentials: 'include',
      })

      const data = await response.json()
      
      if (response.ok) {
        alert('Backup restaurado com sucesso! O sistema será recarregado.')
        window.location.reload()
      } else {
        if (response.status === 401) {
            handleLogout()
            return
        }
        alert(`Erro ao restaurar backup: ${data.error || 'Erro desconhecido'}`)
      }
    } catch (error) {
      console.error('Error restoring backup:', error)
      alert('Erro ao restaurar backup')
    } finally {
      setSettingsLoading(false)
      event.target.value = ''
    }
  }

  const handleLogout = async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' })
    } catch {
      // Ignora erro para garantir saida local.
    }

    setAuthUser(null)
    setAuthMode('login')
  }

  if (authLoading) {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-900 flex items-center justify-center">
        <div className="bg-white border border-slate-200 rounded-xl px-6 py-4 shadow-sm">
          Carregando sessao...
        </div>
      </div>
    )
  }

  if (!authUser) {
    return (
      <div className="min-h-screen bg-slate-100 text-slate-900 flex items-center justify-center px-4">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl shadow-sm p-6 sm:p-8">
          <div className="mb-6">
            <h1 className="text-2xl font-bold tracking-tight">{authCardTitle}</h1>
            <p className="text-sm text-slate-500 mt-1">
              {authMode === 'login' ? 'Acesse para gerenciar seus servidores.' : 'Cadastre um usuario para comecar.'}
            </p>
          </div>

          <form className="space-y-4" onSubmit={handleAuthSubmit}>
            {authMode === 'register' && (
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-500 mb-1">Nome</label>
                <input
                  type="text"
                  value={authForm.name}
                  onChange={(e) => setAuthForm({ ...authForm, name: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Seu nome"
                />
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold uppercase text-slate-500 mb-1">Email</label>
              <input
                type="email"
                value={authForm.email}
                onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="voce@empresa.com"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase text-slate-500 mb-1">Senha</label>
              <input
                type="password"
                value={authForm.password}
                onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Minimo de 8 caracteres"
              />
            </div>

            {authMode === 'register' && (
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-500 mb-1">Confirmar senha</label>
                <input
                  type="password"
                  value={authForm.confirmPassword}
                  onChange={(e) => setAuthForm({ ...authForm, confirmPassword: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Repita a senha"
                />
              </div>
            )}

            {authError && (
              <div className="text-sm text-rose-600 bg-rose-50 border border-rose-100 rounded-lg px-3 py-2">
                {authError}
              </div>
            )}

            <button
              type="submit"
              disabled={authSubmitting}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-400 text-white py-2 rounded-lg text-sm font-medium transition-colors"
            >
              {authSubmitting ? 'Aguarde...' : authMode === 'login' ? 'Entrar' : 'Cadastrar'}
            </button>
          </form>

          <div className="mt-4 text-sm text-slate-600">
            {authMode === 'login' ? 'Nao tem conta?' : 'Ja possui conta?'}{' '}
            <button
              type="button"
              onClick={() => {
                setAuthMode(authMode === 'login' ? 'register' : 'login')
                setAuthError('')
                resetAuthForm()
              }}
              className="text-blue-600 hover:text-blue-700 font-semibold"
            >
              {authMode === 'login' ? 'Cadastre-se' : 'Entrar'}
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="bg-blue-600 p-2 rounded-lg">
              <Server className="text-white w-6 h-6" />
            </div>
            <h1 className="text-xl font-bold tracking-tight">ServList <span className="text-blue-600">Doc</span></h1>
          </div>
          
            <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 text-sm text-slate-600 bg-slate-100 rounded-full px-3 py-1.5">
              <User className="w-4 h-4" />
              <span>{authUser.name}</span>
            </div>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 w-4 h-4" />
              <input 
                type="text" 
                placeholder="Buscar servidor, cliente ou IP..."
                className="pl-10 pr-4 py-2 bg-slate-100 border-none rounded-full text-sm w-64 focus:ring-2 focus:ring-blue-500 transition-all"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <button 
              onClick={checkAllConnectivity}
              disabled={isPinging}
              className="bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors shadow-sm"
            >
              {isPinging ? (
                <Clock className="w-4 h-4 animate-spin" />
              ) : (
                <Wifi className="w-4 h-4" />
              )}
              {isPinging ? 'Verificando...' : 'Verificar Conexão'}
            </button>
            <button 
              onClick={() => setAutoPingEnabled(!autoPingEnabled)}
              className={`${autoPingEnabled ? 'bg-purple-600 hover:bg-purple-700' : 'bg-gray-600 hover:bg-gray-700'} text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors shadow-sm`}
            >
              <Clock className={`w-4 h-4 ${autoPingEnabled ? 'animate-pulse' : ''}`} />
              {autoPingEnabled ? 'Auto-Ping Ativo' : 'Auto-Ping Inativo'}
            </button>
            <button 
              onClick={() => setIsRegisteringUser(true)}
              className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors shadow-sm border border-slate-200"
            >
              <UserPlus className="w-4 h-4" />
              Novo Usuário
            </button>
            {activeTab === 'servers' ? (
              <button 
                onClick={() => setIsAddingServer(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors shadow-sm"
              >
                <Plus className="w-4 h-4" />
                Novo Servidor
              </button>
            ) : (
              <button 
                onClick={() => setIsAddingContract(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors shadow-sm"
              >
                <Plus className="w-4 h-4" />
                Novo Ponto
              </button>
            )}
            <button 
              onClick={handleLogout}
              className="bg-slate-700 hover:bg-slate-800 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors shadow-sm"
            >
              Sair
            </button>
          </div>
        </div>
        <div className="border-t border-slate-200 bg-slate-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex gap-8">
              <button
                onClick={() => setActiveTab('servers')}
                className={`py-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === 'servers'
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
                }`}
              >
                <Server className="w-4 h-4" />
                Servidores
              </button>
              <button
                onClick={() => setActiveTab('contracts')}
                className={`py-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === 'contracts'
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
                }`}
              >
                <FileText className="w-4 h-4" />
                Pontos de Contratação
              </button>
              <button
                onClick={() => setActiveTab('settings')}
                className={`py-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === 'settings'
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
                }`}
              >
                <Settings className="w-4 h-4" />
                Configurações
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'servers' ? (
          <>
            {serversLoading && (
              <div className="flex justify-center mb-6">
                <Clock className="w-8 h-8 text-blue-500 animate-spin" />
              </div>
            )}
            {serversError && (
              <div className="mb-6 p-4 bg-rose-50 border border-rose-200 text-rose-700 rounded-xl flex items-center gap-3">
                <ShieldAlert className="w-5 h-5" />
                <p className="text-sm font-medium">{serversError}</p>
              </div>
            )}
            {/* Stats Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-slate-500 text-sm font-medium">Total de Servidores</span>
                  <Database className="text-blue-500 w-5 h-5" />
                </div>
                <p className="text-2xl font-bold">{servers.length}</p>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-slate-500 text-sm font-medium">Online</span>
                  <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></div>
                </div>
                <p className="text-2xl font-bold">{servers.filter(s => s.status === 'online').length}</p>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-slate-500 text-sm font-medium">Backups em Dia</span>
                  <ShieldCheck className="text-emerald-500 w-5 h-5" />
                </div>
                <p className="text-2xl font-bold">{servers.filter(s => s.backupStatus === 'success').length}</p>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-slate-500 text-sm font-medium">Falhas de Backup</span>
                  <ShieldAlert className="text-rose-500 w-5 h-5" />
                </div>
                <p className="text-2xl font-bold text-rose-600">{servers.filter(s => s.backupStatus === 'failed').length}</p>
              </div>
            </div>

            {/* Ping Dashboard */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 mb-8">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-slate-900">Dashboard de Ping (ms)</h2>
                <span className="text-xs text-slate-500">
                  {pingDashboardEntries.length > 0 ? `${pingDashboardEntries.length} servidor(es) medidos` : 'Sem mediÃ§Ãµes ainda'}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-5">
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs text-slate-500">MÃ©dia</p>
                  <p className="text-xl font-semibold">{averageLatency}ms</p>
                </div>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs text-slate-500">Menor Ping</p>
                  <p className="text-xl font-semibold">{minLatency}ms</p>
                </div>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs text-slate-500">Maior Ping</p>
                  <p className="text-xl font-semibold">{maxLatency}ms</p>
                </div>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs text-slate-500">LatÃªncia Alta (&ge;150ms)</p>
                  <p className="text-xl font-semibold">{criticalLatencyCount}</p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200">
                      <th className="px-3 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">Servidor</th>
                      <th className="px-3 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">Endpoint</th>
                      <th className="px-3 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">Ping</th>
                      <th className="px-3 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">Atualizado em</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {pingDashboardEntries.length > 0 ? (
                      pingDashboardEntries.map((entry) => (
                        <tr key={entry.serverId} className="hover:bg-slate-50">
                          <td className="px-3 py-2">
                            <p className="text-sm font-medium text-slate-800">{entry.name}</p>
                            <p className="text-xs text-slate-500">{entry.client}</p>
                          </td>
                          <td className="px-3 py-2 text-xs font-mono text-slate-600">{entry.endpoint}</td>
                          <td className="px-3 py-2">
                            {entry.ping.isOnline ? (
                              <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${getLatencyBadgeClass(entry.ping.latency)}`}>
                                {entry.ping.latency}ms
                              </span>
                            ) : (
                              <span className="inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium bg-slate-200 text-slate-700">
                                Offline
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2 text-xs text-slate-500">
                            {new Date(entry.ping.lastCheck).toLocaleTimeString()}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={4} className="px-3 py-6 text-center text-sm text-slate-500">
                          Clique em "Verificar ConexÃ£o" para gerar o dashboard de ping em ms.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Server List */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Servidor / Cliente</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Endereço IP</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Backup</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Hardware / OS</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider text-right">Ações</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {filteredServers.length > 0 ? (
                    filteredServers.map((server) => (
                      <tr key={server.id} className="hover:bg-slate-50 transition-colors group">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className={`p-2 rounded-lg ${server.status === 'online' ? 'bg-emerald-50 text-emerald-600' : 'bg-slate-100 text-slate-500'}`}>
                              <Server className="w-5 h-5" />
                            </div>
                            <div>
                              <p className="font-semibold text-slate-900">{server.name}</p>
                              <div className="flex items-center gap-1 text-slate-500 text-xs">
                                <User className="w-3 h-3" />
                                {server.client}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="space-y-1">
                            <div className="flex items-center gap-1.5 text-sm font-mono text-slate-600">
                              <Globe className="w-3.5 h-3.5" />
                              {server.ip}:{server.port}
                            </div>
                            <p className="text-[10px] text-slate-500">
                              Endpoint: <span className="font-mono">{server.endpoint || 'N/A'}</span>
                            </p>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="space-y-1">
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                              server.status === 'online' ? 'bg-emerald-100 text-emerald-700' : 
                              server.status === 'maintenance' ? 'bg-amber-100 text-amber-700' : 
                              'bg-rose-100 text-rose-700'
                            }`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${
                                server.status === 'online' ? 'bg-emerald-500' : 
                                server.status === 'maintenance' ? 'bg-amber-500' : 
                                'bg-rose-500'
                              }`}></span>
                              {server.status.toUpperCase()}
                            </span>
                            {pingStatus[server.id] !== undefined && (
                              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                                pingStatus[server.id].isOnline ? 'bg-blue-100 text-blue-700' : 'bg-orange-100 text-orange-700'
                              }`}>
                                {pingStatus[server.id].isOnline ? (
                                  <Wifi className="w-3 h-3" />
                                ) : (
                                  <WifiOff className="w-3 h-3" />
                                )}
                                {pingStatus[server.id].isOnline ? 'Conectado' : 'Desconectado'}
                              </span>
                            )}
                            {pingStatus[server.id]?.latency > 0 && (
                              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-700">
                                <Clock className="w-3 h-3" />
                                {pingStatus[server.id].latency}ms
                              </span>
                            )}
                            {pingStatus[server.id]?.downtimeStart && (
                              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-100 text-red-700">
                                <Clock className="w-3 h-3" />
                                {calculateDowntime(pingStatus[server.id].downtimeStart!)}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div>
                            <div className={`flex items-center gap-1.5 text-xs font-medium mb-1 ${
                              server.backupStatus === 'success' ? 'text-emerald-600' : 
                              server.backupStatus === 'failed' ? 'text-rose-600' : 
                              'text-slate-500'
                            }`}>
                              {server.backupStatus === 'success' ? <ShieldCheck className="w-3.5 h-3.5" /> : 
                               server.backupStatus === 'failed' ? <ShieldAlert className="w-3.5 h-3.5" /> : 
                               <Clock className="w-3.5 h-3.5" />}
                              {server.backupStatus === 'success' ? 'Sucesso' : 
                               server.backupStatus === 'failed' ? 'Falha' : 
                               'Pendente'}
                            </div>
                            <p className="text-[10px] text-slate-400 font-mono">{server.lastBackup}</p>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="max-w-xs">
                            <div className="flex items-center gap-1.5 text-xs text-slate-600 mb-1">
                              <HardDrive className="w-3 h-3" />
                              {server.os}
                            </div>
                            <p className="text-[10px] text-slate-400 truncate max-w-[150px]">{server.hardware}</p>
                            {server.referencePoint && (
                              <p className="text-[10px] text-slate-500 mt-1 truncate max-w-[150px]" title={server.referencePoint}>
                                Ref: {server.referencePoint}
                              </p>
                            )}
                            {server.mikrotikUser && (
                              <p className="text-[10px] text-slate-500 mt-1 truncate max-w-[150px]" title={server.mikrotikUser}>
                                MikroTik: {server.mikrotikUser}
                              </p>
                            )}
                            {server.mikrotikPassword && (
                              <p className="text-[10px] text-slate-500 truncate max-w-[150px]">
                                Senha: {'*'.repeat(server.mikrotikPassword.length)}
                              </p>
                            )}
                            {server.notes && (
                              <p className="text-[10px] text-blue-500 italic mt-1 truncate max-w-[150px]" title={server.notes}>
                                Note: {server.notes}
                              </p>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button 
                              onClick={() => startEditServer(server)}
                              className="p-1.5 hover:bg-slate-200 rounded text-slate-500 transition-colors"
                              aria-label="Editar servidor"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button 
                              onClick={() => deleteServer(server.id)}
                              className="p-1.5 hover:bg-rose-100 rounded text-rose-500 transition-colors"
                              aria-label="Excluir servidor"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-slate-500">
                        Nenhum servidor encontrado.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
        </>
      ) : activeTab === 'contracts' ? (
          <>
            {contractsLoading && (
              <div className="flex justify-center mb-6">
                <Clock className="w-8 h-8 text-blue-500 animate-spin" />
              </div>
            )}
            {contractsError && (
              <div className="mb-6 p-4 bg-rose-50 border border-rose-200 text-rose-700 rounded-xl flex items-center gap-3">
                <ShieldAlert className="w-5 h-5" />
                <p className="text-sm font-medium">{contractsError}</p>
              </div>
            )}
            
            {/* Contracts List */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Ponto / Fornecedor</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Acesso Equipamento</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Detalhes do Titular</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider">Localização</th>
                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider text-right">Ações</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {contractPoints.length > 0 ? (
                    contractPoints.map((contract) => (
                      <tr key={contract.id} className="hover:bg-slate-50 transition-colors group">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-blue-50 text-blue-600">
                              <FileText className="w-5 h-5" />
                            </div>
                            <div>
                              <p className="font-semibold text-slate-900">{contract.name}</p>
                              <div className="flex items-center gap-1 text-slate-500 text-xs">
                                <User className="w-3 h-3" />
                                {contract.providerName}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="space-y-1">
                             <div className="flex items-center gap-1.5 text-xs text-slate-600">
                                <User className="w-3 h-3" />
                                User: {contract.equipmentUser}
                             </div>
                             <div className="flex items-center gap-1.5 text-xs text-slate-600">
                                <ShieldCheck className="w-3 h-3" />
                                Pass: {'*'.repeat(contract.equipmentPassword?.length || 0)}
                             </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="space-y-1">
                            <p className="text-sm font-medium text-slate-700">{contract.providerHolder}</p>
                            <p className="text-xs text-slate-500">CPF/CNPJ: {contract.providerCpfCnpj}</p>
                            <p className="text-xs text-slate-500">Tel: {contract.providerContact}</p>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-1.5 text-sm text-slate-600">
                            <Globe className="w-3.5 h-3.5" />
                            {contract.providerCity}
                          </div>
                          {contract.notes && (
                            <p className="text-[10px] text-blue-500 italic mt-1 truncate max-w-[150px]" title={contract.notes}>
                              Obs: {contract.notes}
                            </p>
                          )}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button 
                              onClick={() => {
                                setEditingContract(contract)
                                setNewContract(contract)
                                setIsEditingContract(true)
                              }}
                              className="p-1.5 hover:bg-slate-200 rounded text-slate-500 transition-colors"
                              aria-label="Editar contrato"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button 
                              onClick={() => handleDeleteContract(contract.id)}
                              className="p-1.5 hover:bg-rose-100 rounded text-rose-500 transition-colors"
                              aria-label="Excluir contrato"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                        Nenhum ponto de contratação encontrado.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="space-y-6">
            <div className="max-w-2xl mx-auto bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="p-6 border-b border-slate-100">
              <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                <Settings className="w-5 h-5 text-blue-600" />
                Configurações de Backup Email
              </h2>
              <p className="text-sm text-slate-500 mt-1">Configure o envio automático de backups por email.</p>
            </div>
            
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Servidor SMTP</label>
                  <input
                    type="text"
                    value={backupSettings.smtpServer}
                    onChange={e => setBackupSettings({...backupSettings, smtpServer: e.target.value})}
                    placeholder="smtp.gmail.com"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Porta SMTP</label>
                  <input
                    type="text"
                    value={backupSettings.smtpPort}
                    onChange={e => setBackupSettings({...backupSettings, smtpPort: e.target.value})}
                    placeholder="587"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Usuário SMTP</label>
                  <input
                    type="text"
                    value={backupSettings.smtpUser}
                    onChange={e => setBackupSettings({...backupSettings, smtpUser: e.target.value})}
                    placeholder="seu-email@gmail.com"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Senha SMTP</label>
                  <input
                    type="password"
                    value={backupSettings.smtpPassword || ''}
                    onChange={e => setBackupSettings({...backupSettings, smtpPassword: e.target.value})}
                    placeholder="Senha de app"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                  <p className="text-xs text-slate-500 mt-1">Deixe em branco para não alterar.</p>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Email para Receber Backup</label>
                <input
                  type="email"
                  value={backupSettings.backupEmail}
                  onChange={e => setBackupSettings({...backupSettings, backupEmail: e.target.value})}
                  placeholder="admin@empresa.com"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                />
              </div>

              <div className="pt-4 flex items-center justify-end gap-3 border-t border-slate-100 mt-6">
                <button
                  onClick={handleTestBackup}
                  className="px-4 py-2 text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg text-sm font-medium transition-colors"
                >
                  Testar Envio
                </button>
                <button
                  onClick={handleSaveSettings}
                  disabled={settingsLoading}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                >
                  {settingsLoading ? 'Salvando...' : 'Salvar Configurações'}
                </button>
              </div>
            </div>
          </div>

          <div className="max-w-2xl mx-auto bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="p-6 border-b border-slate-100">
              <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                <Database className="w-5 h-5 text-blue-600" />
                Backup Local e Restauração
              </h2>
              <p className="text-sm text-slate-500 mt-1">Gerencie backups manuais do banco de dados.</p>
            </div>
            
            <div className="p-6 space-y-4">
              <div className="flex flex-col sm:flex-row gap-4">
                <button
                  onClick={handleDownloadBackup}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg font-medium transition-colors border border-slate-200"
                >
                  <Download className="w-5 h-5" />
                  Baixar Backup Atual
                </button>
                
                <div className="flex-1">
                  <input
                    type="file"
                    id="restore-backup"
                    accept=".db"
                    className="hidden"
                    onChange={handleRestoreBackup}
                  />
                  <label
                    htmlFor="restore-backup"
                    className="flex items-center justify-center gap-2 px-4 py-3 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg font-medium transition-colors border border-slate-200 cursor-pointer w-full"
                  >
                    <Upload className="w-5 h-5" />
                    Restaurar Backup
                  </label>
                </div>
              </div>
              
              <p className="text-xs text-slate-500 text-center">
                Nota: Ao restaurar um backup, o sistema criará automaticamente uma cópia de segurança do banco atual antes de sobrescrevê-lo.
              </p>
            </div>
          </div>
          </div>
        )}
      </main>

      {/* Add/Edit Server Modal */}
      {(isAddingServer || isEditingServer) && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-lg max-h-[90vh] overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
              <h2 className="text-lg font-bold">{isAddingServer ? 'Cadastrar Novo Servidor' : 'Editar Servidor'}</h2>
              <button 
                onClick={() => {
                  setIsAddingServer(false)
                  setIsEditingServer(false)
                  setEditingServer(null)
                  setNewServer({ status: 'online', backupStatus: 'pending', port: '80', endpoint: '', referencePoint: '', mikrotikUser: '', mikrotikPassword: '' })
                }}
                className="text-slate-400 hover:text-slate-600 transition-colors"
                aria-label="Fechar modal"
              >
                <Plus className="w-6 h-6 rotate-45" />
              </button>
            </div>
            
            <div className="p-4 sm:p-5 space-y-3 overflow-y-auto max-h-[calc(90vh-72px)]">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Nome do Servidor</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="Ex: SRV-APP-01"
                    value={newServer.name || ''}
                    onChange={e => setNewServer({...newServer, name: e.target.value})}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Cliente</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="Ex: Loja Modelo"
                    value={newServer.client || ''}
                    onChange={e => setNewServer({...newServer, client: e.target.value})}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Endereço IP</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="192.168.x.x"
                    value={newServer.ip || ''}
                    onChange={e => setNewServer({...newServer, ip: e.target.value})}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Porta</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="80"
                    value={newServer.port || ''}
                    onChange={e => setNewServer({...newServer, port: e.target.value})}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Endpoint</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="api.cliente.local"
                    value={newServer.endpoint || ''}
                    onChange={e => setNewServer({...newServer, endpoint: e.target.value})}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Endereco / Ponto de Referencia</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="Ex: Sala TI - fundos"
                    value={newServer.referencePoint || ''}
                    onChange={e => setNewServer({...newServer, referencePoint: e.target.value})}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Usuario MikroTik</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="admin"
                    value={newServer.mikrotikUser || ''}
                    onChange={e => setNewServer({...newServer, mikrotikUser: e.target.value})}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Senha MikroTik</label>
                  <input 
                    type="password" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="******"
                    value={newServer.mikrotikPassword || ''}
                    onChange={e => setNewServer({...newServer, mikrotikPassword: e.target.value})}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Sistema Operacional</label>
                <input 
                  type="text" 
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  placeholder="Ubuntu, Windows, etc"
                  value={newServer.os || ''}
                  onChange={e => setNewServer({...newServer, os: e.target.value})}
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Hardware</label>
                <input 
                  type="text" 
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  placeholder="CPU, RAM, Disco..."
                  value={newServer.hardware || ''}
                  onChange={e => setNewServer({...newServer, hardware: e.target.value})}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</label>
                  <select 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    onChange={e => setNewServer({...newServer, status: e.target.value as 'online' | 'offline' | 'maintenance'})}
                    value={newServer.status || 'online'}
                  >
                    <option value="online">Online</option>
                    <option value="offline">Offline</option>
                    <option value="maintenance">Manutenção</option>
                  </select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Status do Backup</label>
                  <select 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    onChange={e => setNewServer({...newServer, backupStatus: e.target.value as 'success' | 'failed' | 'pending'})}
                    value={newServer.backupStatus || 'pending'}
                  >
                    <option value="success">Sucesso</option>
                    <option value="failed">Falha</option>
                    <option value="pending">Pendente</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Notas / Observações</label>
                <textarea 
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none min-h-[80px] resize-none"
                  placeholder="Informações adicionais..."
                  value={newServer.notes || ''}
                  onChange={e => setNewServer({...newServer, notes: e.target.value})}
                />
              </div>

              <div className="sticky bottom-0 bg-white pt-3 flex gap-3">
                <button 
                  onClick={() => {
                    setIsAddingServer(false)
                    setIsEditingServer(false)
                    setEditingServer(null)
                    setNewServer({ status: 'online', backupStatus: 'pending', port: '80', endpoint: '', referencePoint: '', mikrotikUser: '', mikrotikPassword: '' })
                  }}
                  className="flex-1 px-4 py-2 border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
                >
                  Cancelar
                </button>
                <button 
                  onClick={isAddingServer ? handleAddServer : handleEditServer}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors shadow-sm"
                >
                  {isAddingServer ? 'Salvar Servidor' : 'Atualizar Servidor'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add/Edit Contract Point Modal */}
      {(isAddingContract || isEditingContract) && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-lg max-h-[90vh] overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
              <h2 className="text-lg font-bold">{isAddingContract ? 'Novo Ponto de Contratação' : 'Editar Ponto de Contratação'}</h2>
              <button 
                onClick={() => {
                  setIsAddingContract(false)
                  setIsEditingContract(false)
                  setEditingContract(null)
                  setNewContract({})
                }}
                className="text-slate-400 hover:text-slate-600 transition-colors"
                aria-label="Fechar modal"
              >
                <Plus className="w-6 h-6 rotate-45" />
              </button>
            </div>
            
            <div className="p-4 sm:p-5 space-y-3 overflow-y-auto max-h-[calc(90vh-72px)]">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Nome do Ponto</label>
                <input 
                  type="text" 
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  placeholder="Ex: Ponto Principal"
                  value={newContract.name || ''}
                  onChange={e => setNewContract({...newContract, name: e.target.value})}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Usuário Equipamento</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="admin"
                    value={newContract.equipmentUser || ''}
                    onChange={e => setNewContract({...newContract, equipmentUser: e.target.value})}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Senha Equipamento</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="******"
                    value={newContract.equipmentPassword || ''}
                    onChange={e => setNewContract({...newContract, equipmentPassword: e.target.value})}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Nome do Fornecedor</label>
                <input 
                  type="text" 
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  placeholder="Ex: Provedor X"
                  value={newContract.providerName || ''}
                  onChange={e => setNewContract({...newContract, providerName: e.target.value})}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Titular do Cadastro</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="Nome do Titular"
                    value={newContract.providerHolder || ''}
                    onChange={e => setNewContract({...newContract, providerHolder: e.target.value})}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">CPF / CNPJ</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="000.000.000-00"
                    value={newContract.providerCpfCnpj || ''}
                    onChange={e => setNewContract({...newContract, providerCpfCnpj: e.target.value})}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Telefone</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="(00) 00000-0000"
                    value={newContract.providerContact || ''}
                    onChange={e => setNewContract({...newContract, providerContact: e.target.value})}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Cidade</label>
                  <input 
                    type="text" 
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                    placeholder="Cidade - UF"
                    value={newContract.providerCity || ''}
                    onChange={e => setNewContract({...newContract, providerCity: e.target.value})}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Notas / Observações</label>
                <textarea 
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none min-h-[80px] resize-none"
                  placeholder="Informações adicionais..."
                  value={newContract.notes || ''}
                  onChange={e => setNewContract({...newContract, notes: e.target.value})}
                />
              </div>

              <div className="sticky bottom-0 bg-white pt-3 flex gap-3">
                <button 
                  onClick={() => {
                    setIsAddingContract(false)
                    setIsEditingContract(false)
                    setEditingContract(null)
                    setNewContract({})
                  }}
                  className="flex-1 px-4 py-2 border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
                >
                  Cancelar
                </button>
                <button 
                  onClick={isAddingContract ? handleAddContract : handleUpdateContract}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors shadow-sm"
                >
                  {isAddingContract ? 'Salvar Ponto' : 'Atualizar Ponto'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Internal User Registration Modal */ }
      {isRegisteringUser && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md max-h-[90vh] overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
              <div className="flex items-center gap-2">
                <div className="p-2 bg-blue-50 rounded-lg">
                  <UserPlus className="w-5 h-5 text-blue-600" />
                </div>
                <h2 className="text-lg font-bold text-slate-800">Novo Usuário</h2>
              </div>
              <button 
                onClick={() => {
                  setIsRegisteringUser(false)
                  resetAuthForm()
                  setAuthError('')
                }}
                className="text-slate-400 hover:text-slate-600 transition-colors p-1 hover:bg-slate-100 rounded-full"
                aria-label="Fechar modal"
              >
                <Plus className="w-6 h-6 rotate-45" />
              </button>
            </div>
            
            <form onSubmit={handleInternalRegister} className="p-6 space-y-4">
              {authError && (
                <div className="p-3 bg-rose-50 border border-rose-100 rounded-lg text-rose-600 text-sm flex items-center gap-2 animate-shake">
                  <div className="w-1.5 h-1.5 bg-rose-500 rounded-full" />
                  {authError}
                </div>
              )}

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Nome Completo</label>
                <input 
                  type="text" 
                  required
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none transition-all"
                  placeholder="Nome do usuário"
                  value={authForm.name}
                  onChange={e => setAuthForm({...authForm, name: e.target.value})}
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Email</label>
                <input 
                  type="email" 
                  required
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none transition-all"
                  placeholder="email@exemplo.com"
                  value={authForm.email}
                  onChange={e => setAuthForm({...authForm, email: e.target.value})}
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Senha</label>
                <input 
                  type="password" 
                  required
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none transition-all"
                  placeholder="******"
                  value={authForm.password}
                  onChange={e => setAuthForm({...authForm, password: e.target.value})}
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Confirmar Senha</label>
                <input 
                  type="password" 
                  required
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none transition-all"
                  placeholder="******"
                  value={authForm.confirmPassword}
                  onChange={e => setAuthForm({...authForm, confirmPassword: e.target.value})}
                />
              </div>

              <div className="pt-4 flex gap-3">
                <button 
                  type="button"
                  onClick={() => {
                    setIsRegisteringUser(false)
                    resetAuthForm()
                    setAuthError('')
                  }}
                  className="flex-1 px-4 py-2.5 border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
                >
                  Cancelar
                </button>
                <button 
                  type="submit"
                  disabled={authSubmitting}
                  className="flex-1 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-lg text-sm font-medium transition-colors shadow-sm flex items-center justify-center gap-2"
                >
                  {authSubmitting ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Cadastrando...
                    </>
                  ) : (
                    'Criar Usuário'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
