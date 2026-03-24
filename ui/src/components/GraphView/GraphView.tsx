/**
 * GraphView — interactive Cytoscape.js-powered scan graph visualization.
 *
 * Fetches /api/graph and renders a force-directed graph of assets, targets,
 * services, technologies, vulnerabilities, and exploits.
 *
 * Dependencies (install with npm):
 *   npm install cytoscape @types/cytoscape
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import cytoscape, {
    Core,
    ElementDefinition,
    NodeSingular,
    StylesheetStyle,
} from 'cytoscape';
import './GraphStyles.css';

// ── Types ──────────────────────────────────────────────────────────────────

type NodeType = 'asset' | 'target' | 'service' | 'tech' | 'vuln' | 'exploit';

interface GraphNode {
    id: string;
    type: NodeType;
    label: string;
    data: Record<string, unknown>;
}

interface GraphEdge {
    id: string;
    from: string;
    to: string;
    kind: 'owns' | 'exposes' | 'runs' | 'affected-by' | 'exploits';
}

interface ScanGraph {
    nodes: GraphNode[];
    edges: GraphEdge[];
}

interface NodeStyle {
    bg: string;
    border: string;
    shape: string;
}

// ── Constants ─────────────────────────────────────────────────────────────

const NODE_STYLE: Record<NodeType, NodeStyle> = {
    asset:   { bg: '#8b5cf6', border: '#7c3aed', shape: 'hexagon'   },
    target:  { bg: '#0ea5e9', border: '#0284c7', shape: 'ellipse'   },
    service: { bg: '#10b981', border: '#059669', shape: 'diamond'   },
    tech:    { bg: '#f59e0b', border: '#d97706', shape: 'rectangle' },
    vuln:    { bg: '#ef4444', border: '#dc2626', shape: 'triangle'  },
    exploit: { bg: '#dc2626', border: '#991b1b', shape: 'star'      },
};

const EDGE_COLOR: Record<string, string> = {
    'owns':        '#8b5cf6',
    'exposes':     '#0ea5e9',
    'runs':        '#10b981',
    'affected-by': '#ef4444',
    'exploits':    '#dc2626',
};

const ALL_TYPES: NodeType[]  = ['asset', 'target', 'service', 'tech', 'vuln', 'exploit'];
const ALL_SEVS               = ['critical', 'high', 'medium', 'low', 'info'];
const ALL_KINDS               = ['owns', 'exposes', 'runs', 'affected-by', 'exploits'];

// ── Component ─────────────────────────────────────────────────────────────

export function GraphView() {
    const cyContainerRef = useRef<HTMLDivElement>(null);
    const cyRef          = useRef<Core | null>(null);

    const [graph,        setGraph]        = useState<ScanGraph | null>(null);
    const [loading,      setLoading]      = useState(false);
    const [error,        setError]        = useState<string | null>(null);
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

    // Filter state
    const [activeTypes, setActiveTypes] = useState<Set<string>>(new Set(ALL_TYPES));
    const [activeSevs,  setActiveSevs]  = useState<Set<string>>(new Set(ALL_SEVS));
    const [activeKinds, setActiveKinds] = useState<Set<string>>(new Set(ALL_KINDS));

    // ── Data fetching ──────────────────────────────────────────────────────

    const fetchGraph = useCallback(async () => {
        setLoading(true);
        setError(null);
        setSelectedNode(null);
        try {
            const resp = await fetch('/api/graph');
            if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
            const data: ScanGraph = await resp.json();
            setGraph(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchGraph(); }, [fetchGraph]);

    // ── Cytoscape rendering ────────────────────────────────────────────────

    useEffect(() => {
        if (!graph || !cyContainerRef.current) return;

        if (cyRef.current) {
            cyRef.current.destroy();
            cyRef.current = null;
        }

        const elements = buildElements(graph, activeTypes, activeSevs, activeKinds);
        const stylesheet = buildStylesheet();

        const cy = cytoscape({
            container: cyContainerRef.current,
            elements,
            style: stylesheet,
            layout: {
                name: 'breadthfirst',
                directed: true,
                spacingFactor: 1.4,
                avoidOverlap: true,
                padding: 40,
            } as cytoscape.BreadthFirstLayoutOptions,
            wheelSensitivity: 0.3,
            minZoom: 0.05,
            maxZoom: 4,
        });

        cy.on('tap', 'node', (evt) => {
            const nodeData = evt.target.data() as { nodeData: GraphNode };
            if (nodeData?.nodeData) setSelectedNode(nodeData.nodeData);
        });

        cy.on('tap', (evt) => {
            if (evt.target === cy) setSelectedNode(null);
        });

        cyRef.current = cy;

        return () => {
            cy.destroy();
            cyRef.current = null;
        };
    }, [graph, activeTypes, activeSevs, activeKinds]);

    // ── Stats ──────────────────────────────────────────────────────────────

    const stats = graph ? {
        Nodes:    graph.nodes.length,
        Edges:    graph.edges.length,
        Assets:   graph.nodes.filter(n => n.type === 'asset').length,
        Targets:  graph.nodes.filter(n => n.type === 'target').length,
        Services: graph.nodes.filter(n => n.type === 'service').length,
        Techs:    graph.nodes.filter(n => n.type === 'tech').length,
        Vulns:    graph.nodes.filter(n => n.type === 'vuln').length,
        Exploits: graph.nodes.filter(n => n.type === 'exploit').length,
    } : null;

    // ── Filter toggle helpers ─────────────────────────────────────────────

    function toggleSet(set: Set<string>, val: string): Set<string> {
        const next = new Set(set);
        next.has(val) ? next.delete(val) : next.add(val);
        return next;
    }

    // ── Render ────────────────────────────────────────────────────────────

    return (
        <div className="gv-root">
            {/* ── Sidebar ── */}
            <div className="gv-sidebar">
                <p className="gv-sidebar-title">Scan Graph</p>

                <button
                    className="gv-reload-btn"
                    onClick={fetchGraph}
                    disabled={loading}
                >
                    {loading ? '⟳ Loading…' : '⟳ Rebuild Graph'}
                </button>

                {/* Node type filters */}
                <div>
                    <p className="gv-sidebar-title" style={{ marginBottom: 6 }}>Node Types</p>
                    <div className="gv-filter-section">
                        {ALL_TYPES.map(type => {
                            const s = NODE_STYLE[type];
                            return (
                                <label key={type} className="gv-filter-row">
                                    <input
                                        type="checkbox"
                                        checked={activeTypes.has(type)}
                                        onChange={() => setActiveTypes(prev => toggleSet(prev, type))}
                                    />
                                    <span className="gv-dot" style={{ background: s.bg }} />
                                    {type.charAt(0).toUpperCase() + type.slice(1)}
                                </label>
                            );
                        })}
                    </div>
                </div>

                {/* Severity filter (applies to vuln + exploit) */}
                <div>
                    <p className="gv-sidebar-title" style={{ marginBottom: 6 }}>Vuln Severity</p>
                    <div className="gv-filter-section">
                        {ALL_SEVS.map(sev => (
                            <label key={sev} className="gv-filter-row">
                                <input
                                    type="checkbox"
                                    checked={activeSevs.has(sev)}
                                    onChange={() => setActiveSevs(prev => toggleSet(prev, sev))}
                                />
                                {sev.charAt(0).toUpperCase() + sev.slice(1)}
                            </label>
                        ))}
                    </div>
                </div>

                {/* Edge kind filter */}
                <div>
                    <p className="gv-sidebar-title" style={{ marginBottom: 6 }}>Edge Kind</p>
                    <div className="gv-filter-section">
                        {ALL_KINDS.map(kind => (
                            <label key={kind} className="gv-filter-row">
                                <input
                                    type="checkbox"
                                    checked={activeKinds.has(kind)}
                                    onChange={() => setActiveKinds(prev => toggleSet(prev, kind))}
                                />
                                {kind}
                            </label>
                        ))}
                    </div>
                </div>

                {/* Stats */}
                {stats && (
                    <div>
                        <p className="gv-sidebar-title" style={{ marginBottom: 6 }}>Stats</p>
                        <div className="gv-stats-grid">
                            {Object.entries(stats).map(([k, v]) => (
                                <div key={k} className="gv-stat-card">
                                    <div className="gv-stat-val">{v}</div>
                                    <div className="gv-stat-lbl">{k}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            {/* ── Canvas ── */}
            <div className="gv-canvas-wrapper">
                <div ref={cyContainerRef} className="gv-canvas" />
                {loading && !graph && (
                    <div className="gv-loading">Loading graph…</div>
                )}
                {error && (
                    <div className="gv-loading gv-error">Error: {error}</div>
                )}
                {!loading && !error && graph?.nodes.length === 0 && (
                    <div className="gv-loading">
                        No data yet. Start a scan to populate the graph.
                    </div>
                )}
            </div>

            {/* ── Detail Panel ── */}
            {selectedNode && (
                <div className="gv-detail">
                    <div className="gv-detail-header">
                        <span className="gv-detail-header-title">{selectedNode.label}</span>
                        <button className="gv-detail-close" onClick={() => setSelectedNode(null)}>×</button>
                    </div>
                    <div className="gv-detail-body">
                        <NodeDetailPanel node={selectedNode} />
                    </div>
                </div>
            )}
        </div>
    );
}

// ── NodeDetailPanel ────────────────────────────────────────────────────────

function NodeDetailPanel({ node }: { node: GraphNode }) {
    const s = NODE_STYLE[node.type];
    const raw = node.data;
    const sev = typeof raw?.severity === 'string' ? raw.severity.toLowerCase() : null;

    return (
        <>
            {/* Type badge */}
            <div className={`gv-badge gv-badge-type`}
                style={{ background: `${s.bg}22`, color: s.bg, border: `1px solid ${s.bg}44` }}>
                {node.type}
            </div>

            {/* Severity badge */}
            {sev && (
                <div style={{ marginTop: 6 }}>
                    <span className={`gv-badge gv-badge-${sev}`}>{sev}</span>
                </div>
            )}

            {/* KEV badge */}
            {raw?.is_kev && (
                <div style={{ marginTop: 6 }}>
                    <span className="gv-badge gv-badge-kev">⚑ CISA KEV</span>
                </div>
            )}

            {/* Properties */}
            <p className="gv-detail-section-title">Properties</p>
            {Object.entries(raw).map(([k, v]) => {
                if (v === null || v === undefined || v === '' || v === false) return null;
                if (k === 'severity') return null;
                const display = typeof v === 'boolean' ? 'yes' : String(v);
                return (
                    <div key={k} className="gv-detail-row">
                        <span className="gv-detail-key">{k.replace(/_/g, ' ')}</span>
                        <span className="gv-detail-val">{display}</span>
                    </div>
                );
            })}

            {/* Deep-link to Target/Asset detail pages */}
            {node.type === 'target' && raw?.id && (
                <a href={`/target/${raw.id}`} className="gv-detail-link">
                    Open Target Details →
                </a>
            )}
            {node.type === 'asset' && raw?.id && (
                <a href={`/asset/${raw.id}`} className="gv-detail-link">
                    Open Asset Overview →
                </a>
            )}
        </>
    );
}

// ── Cytoscape helpers ──────────────────────────────────────────────────────

function buildElements(
    g: ScanGraph,
    activeTypes: Set<string>,
    activeSevs: Set<string>,
    activeKinds: Set<string>,
): ElementDefinition[] {
    const visibleNodeIDs = new Set<string>();

    const nodes: ElementDefinition[] = (g.nodes ?? [])
        .filter(n => {
            if (!activeTypes.has(n.type)) return false;
            if (n.type === 'vuln' || n.type === 'exploit') {
                const sev = ((n.data?.severity as string) || 'info').toLowerCase();
                if (!activeSevs.has(sev)) return false;
            }
            return true;
        })
        .map(n => {
            visibleNodeIDs.add(n.id);
            return {
                data: {
                    id: n.id,
                    label: n.label.length > 22 ? n.label.slice(0, 22) + '…' : n.label,
                    type: n.type,
                    nodeData: n,   // full node for detail panel
                },
            };
        });

    const edges: ElementDefinition[] = (g.edges ?? [])
        .filter(e =>
            visibleNodeIDs.has(e.from) &&
            visibleNodeIDs.has(e.to) &&
            activeKinds.has(e.kind),
        )
        .map(e => ({
            data: { id: e.id, source: e.from, target: e.to, kind: e.kind },
        }));

    return [...nodes, ...edges];
}

function buildStylesheet(): StylesheetStyle[] {
    const nodeStyles: StylesheetStyle[] = (Object.entries(NODE_STYLE) as [NodeType, NodeStyle][])
        .map(([type, s]) => ({
            selector: `node[type="${type}"]`,
            style: {
                'background-color': s.bg,
                'border-color': s.border,
                'border-width': 2,
                'shape': s.shape as cytoscape.Css.Node['shape'],
                'width': type === 'asset' ? 54 : type === 'exploit' ? 44 : 38,
                'height': type === 'asset' ? 54 : type === 'exploit' ? 44 : 38,
                'label': 'data(label)',
                'color': '#e2e8f0',
                'font-size': 10,
                'font-family': 'Inter, sans-serif',
                'text-valign': 'bottom' as const,
                'text-margin-y': 4,
                'text-outline-width': 2,
                'text-outline-color': '#07080a',
            },
        }));

    const edgeStyles: StylesheetStyle[] = Object.entries(EDGE_COLOR).map(([kind, color]) => ({
        selector: `edge[kind="${kind}"]`,
        style: {
            'line-color': color,
            'target-arrow-color': color,
            'opacity': 0.7,
        },
    }));

    return [
        {
            selector: 'node',
            style: {
                'border-width': 2,
                'transition-property': 'border-width, border-color',
                'transition-duration': '150ms',
            },
        },
        {
            selector: 'node:selected',
            style: { 'border-width': 4, 'border-color': '#fff' },
        },
        {
            selector: 'edge',
            style: {
                'width': 1.5,
                'curve-style': 'bezier',
                'target-arrow-shape': 'triangle',
                'arrow-scale': 0.8,
                'font-size': 9,
                'color': '#64748b',
                'label': 'data(kind)',
                'text-rotation': 'autorotate',
                'text-margin-y': -6,
                'font-family': 'Inter, sans-serif',
                'text-outline-width': 2,
                'text-outline-color': '#07080a',
            },
        },
        ...nodeStyles,
        ...edgeStyles,
    ];
}
