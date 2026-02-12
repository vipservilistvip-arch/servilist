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
  WifiOff
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

// Safe JSON parse with fallback
function safeParse<T>(jsonString: string, fallback: T): T {
  try {
    return JSON.parse(jsonString) as T
  } catch {
    console.error('Failed to parse JSON')
    return fallback
  }
}

// Mock data for initial look
const mockData: ServerData[] = [
  {
    id: '1',
    name: 'SRV-DB-PROD',
    client: 'Posto Central',
    ip: '10.0.0.15',
    port: '3306',
    endpoint: 'db.postocentral.local',
    referencePoint: 'Matriz - Sala do CPD, 2o andar',
    mikrotikUser: 'admin',
    mikrotikPassword: 'admin123',
    os: 'Windows Server 2019',
    hardware: '32GB RAM, 8 vCPU, 1TB SSD',
    status: 'online',
    backupStatus: 'success',
    lastBackup: '2026-02-10 22:00',
    notes: 'Banco de dados principal do ERP'
  },
  {
    id: '2',
    name: 'SRV-APP-WEB',
    client: 'Mercado Silva',
    ip: '192.168.1.50',
    port: '80',
    endpoint: 'app.mercadosilva.local',
    referencePoint: 'Filial Centro - Rack proximo ao caixa',
    mikrotikUser: 'suporte',
    mikrotikPassword: 'mk@2026',
    os: 'Ubuntu 22.04 LTS',
    hardware: '8GB RAM, 2 vCPU, 240GB SSD',
    status: 'online',
    backupStatus: 'failed',
    lastBackup: '2026-02-09 03:00',
    notes: 'Servidor de hospedagem do site e API'
  }
]

const PING_TIMEOUT_MS = 1500
const PING_ATTEMPTS = 3

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
  const [servers, setServers] = useState<ServerData[]>(() => {
    const saved = localStorage.getItem('servlist_servers')
    return saved ? safeParse(saved, []) : mockData
  })
  
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
  const [pingStatus, setPingStatus] = useState<{ [key: string]: PingStatus }>({})
  const [isPinging, setIsPinging] = useState(false)
  const [autoPingEnabled, setAutoPingEnabled] = useState(false)

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

  // Save to localStorage whenever servers change
  useEffect(() => {
    localStorage.setItem('servlist_servers', JSON.stringify(servers))
  }, [servers])

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

  const handleAddServer = () => {
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
      const updated = [...servers, server]
      setServers(updated)
      setIsAddingServer(false)
      setNewServer({ status: 'online', backupStatus: 'pending', port: '80', endpoint: '', referencePoint: '', mikrotikUser: '', mikrotikPassword: '' })
    }
  }

  const handleEditServer = () => {
    if (editingServer && newServer.name && newServer.client) {
      const updated = servers.map(server => 
        server.id === editingServer.id 
          ? { 
              ...server, 
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
              notes: newServer.notes || '' 
            }
          : server
      )
      setServers(updated)
      setIsEditingServer(false)
      setEditingServer(null)
      setNewServer({ status: 'online', backupStatus: 'pending', port: '80', endpoint: '', referencePoint: '', mikrotikUser: '', mikrotikPassword: '' })
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

  const deleteServer = (id: string) => {
    const updated = servers.filter(s => s.id !== id)
    setServers(updated)
    localStorage.setItem('servlist_servers', JSON.stringify(updated))
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
              onClick={() => setIsAddingServer(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors shadow-sm"
            >
              <Plus className="w-4 h-4" />
              Novo Servidor
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
    </div>
  )
}

export default App
