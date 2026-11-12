import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { evidenceState, graphElements, kindName, nodeName } from '../view-model.mjs';
import { FLAG_NAME, onlyOutsideGuard } from '../boundary-model.mjs';
import { displayValue, fieldLabel, fieldValue } from '../labels.mjs';
import { Icon, Notice, Status } from '../components/common.jsx';
import { Identifier } from '../components/identifier.jsx';

// The graph opens no smaller than this zoom, so node and edge text stays readable.
const READABLE_ZOOM = 0.75;
export function Graph({
  graph,
  policyEvidence,
  onSelect,
  outsideGuard = null,
  flagStatus = null,
  tenantId = null,
  selected = null,
}) {
  const container = useRef(null),
    instance = useRef(null);
  const [labels, setLabels] = useState(true),
    [outsideOnly, setOutsideOnly] = useState(false),
    [error, setError] = useState(''),
    [empty, setEmpty] = useState(false),
    [clipped, setClipped] = useState(false);
  useEffect(() => {
    setError('');
    setEmpty(false);
    let elements;
    try {
      elements = graphElements(graph, policyEvidence, { outsideGuard, flagStatus, tenantId, boxes: true });
      if (outsideOnly) elements = onlyOutsideGuard(elements);
    } catch {
      setError('This graph could not be displayed safely. Select another agent.');
      return;
    }
    setEmpty(outsideOnly && !elements.length);
    const cy = cytoscape({
      container: container.current,
      elements,
      minZoom: 0.25,
      maxZoom: 2.5,
      layout: { name: 'preset' },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#e8edf4',
            'border-width': 1.5,
            'border-color': '#b6c5d7',
            width: 38,
            height: 38,
            label: 'data(label)',
            'font-size': 11,
            'font-family': 'Inter, system-ui, sans-serif',
            color: '#314358',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-wrap': 'ellipsis',
            'text-max-width': 100,
            'text-background-color': '#f9fbfd',
            'text-background-opacity': 0.85,
            'text-background-padding': 2,
          },
        },
        {
          selector: 'node.agent',
          style: {
            'background-color': '#274b77',
            'border-color': '#183b65',
            width: 52,
            height: 52,
            color: '#173754',
            'font-weight': 600,
          },
        },
        {
          selector: 'node.task',
          style: { 'background-color': '#dcecf7', 'border-color': '#78a6c8', shape: 'round-rectangle' },
        },
        {
          selector: 'node.resource',
          style: { 'background-color': '#e1ede6', 'border-color': '#86ab96', shape: 'round-rectangle' },
        },
        { selector: 'node.mcp', style: { 'background-color': '#e9e3f5', 'border-color': '#ab99c9', shape: 'hexagon' } },
        {
          selector: 'node.identity',
          style: { 'background-color': '#f5ead7', 'border-color': '#c6a36c', shape: 'diamond', width: 43, height: 43 },
        },
        {
          selector: 'node.unavailable',
          style: { 'border-style': 'dashed', 'border-color': '#bd923e', 'background-color': '#fbf3df' },
        },
        {
          selector: 'node.conditional',
          style: { 'border-style': 'dotted', 'border-width': 3, 'border-color': '#ac863d' },
        },
        { selector: 'node.blocked', style: { 'background-color': '#f9e1df', 'border-color': '#c66d66' } },
        { selector: 'node:selected', style: { 'border-width': 3.5, 'border-color': '#2b77be', 'overlay-opacity': 0 } },
        {
          selector: 'edge',
          style: {
            width: 1.4,
            'line-color': '#b5c3d2',
            'target-arrow-color': '#a2b2c5',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.65,
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 10,
            color: '#5a6a7c',
            'text-rotation': 'autorotate',
            'text-background-color': '#f9fbfd',
            'text-background-opacity': 0.9,
            'text-background-padding': 3,
          },
        },
        {
          selector: 'edge.association',
          style: { 'line-style': 'dashed', 'line-color': '#c0a77d', 'target-arrow-color': '#c0a77d' },
        },
        {
          selector: 'edge.unavailable',
          style: { 'line-style': 'dashed', 'line-color': '#b9934e', 'target-arrow-color': '#b9934e' },
        },
        {
          selector: 'edge.conditional',
          style: { 'line-style': 'dotted', 'line-color': '#ac863d', 'target-arrow-color': '#ac863d' },
        },
        {
          selector: 'edge.policy-candidate',
          style: {
            'line-style': 'dashed',
            'line-color': '#a37834',
            'target-arrow-color': '#a37834',
            width: 2,
            color: '#85632e',
          },
        },
        {
          selector: 'node.direct-access, node.outside-node',
          style: {
            'background-color': '#fbe9e7',
            'border-color': '#b3261e',
            'border-style': 'dashed',
            shape: 'round-tag',
          },
        },
        {
          selector: 'node.outside-node.resource',
          style: { 'background-color': '#fbf3df', 'border-color': '#a1691b', shape: 'round-rectangle' },
        },
        // The flag name sits on its own line so the ellipsis never hides it.
        {
          selector: 'node.flag-exposed, node.flag-mitigated, node.flag-unknown',
          style: { 'text-wrap': 'wrap', 'text-max-width': 160 },
        },
        { selector: 'node.flag-exposed', style: { 'border-color': '#b3261e', 'border-width': 4, color: '#8c1d18' } },
        { selector: 'node.flag-mitigated', style: { 'border-color': '#c48a1c', 'border-width': 4, color: '#6d4c10' } },
        {
          selector: 'node.flag-unknown',
          style: { 'border-color': '#7b8794', 'border-width': 4, 'border-style': 'dashed' },
        },
        {
          selector: 'node.box',
          style: {
            shape: 'round-rectangle',
            'background-color': '#f4f7fa',
            'background-opacity': 0.55,
            'border-width': 1.2,
            'border-color': '#9fb1c4',
            padding: 18,
            'text-max-width': 400,
            label: 'data(label)',
            'text-valign': 'top',
            'text-halign': 'center',
            'text-margin-y': -4,
            'font-size': 10,
            'font-weight': 600,
            color: '#3d5166',
            'text-background-opacity': 0,
          },
        },
        {
          selector: 'node.box-team',
          style: { 'background-color': '#eaf1f8', 'border-style': 'dashed', 'border-color': '#7f9bb8' },
        },
        {
          selector: 'edge.outside-guard',
          style: {
            'line-style': 'dashed',
            'line-color': '#b3261e',
            'target-arrow-color': '#b3261e',
            width: 2.2,
            color: '#8c1d18',
          },
        },
        {
          selector: 'edge.identity-reach',
          style: {
            'line-style': 'dashed',
            'line-color': '#c48a1c',
            'target-arrow-color': '#c48a1c',
            width: 2.2,
            color: '#6d4c10',
          },
        },
        {
          selector: 'edge.crosses-box',
          style: { 'underlay-color': '#6b4fbb', 'underlay-opacity': 0.22, 'underlay-padding': 4, width: 2.6 },
        },
      ],
    });
    const leaves = cy.nodes(':childless');
    const boxes = leaves.map(node => node.boundingBox({ includeLabels: true, includeOverlays: false }));
    const height = Math.max(1, ...boxes.map(box => box.h));
    const size = Math.max(height, ...boxes.map(box => box.w));
    // Breadthfirst uses the widest label for both axes. Keep label-aware
    // horizontal clearance, but reserve actual label height plus a row gap
    // vertically so fitting a compact neighborhood does not shrink its text.
    const rowScale = Math.min(1, (height + 12) / size);
    // Boxes size themselves around their children, so only leaf nodes take part in the layout.
    cy.elements()
      .not(':parent')
      .layout({
        name: 'breadthfirst',
        directed: false,
        padding: 32,
        spacingFactor: 1.05,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true,
        transform: (_node, point) => ({ x: point.x, y: point.y * rowScale }),
      })
      .run();
    // Nodes outside every box (provider resources, identity-reach buckets) move to a row below the boxes,
    // so a box never appears to contain them.
    const loose = leaves.filter(node => node.parent().empty()),
      parents = cy.nodes(':parent');
    if (parents.nonempty() && loose.nonempty()) {
      const area = parents.boundingBox({ includeLabels: true }),
        widths = loose.map(node => node.boundingBox({ includeLabels: true }).w);
      const gap = 28,
        total = widths.reduce((sum, width) => sum + width, 0) + gap * (widths.length - 1);
      let x = (area.x1 + area.x2) / 2 - total / 2;
      loose.forEach((node, index) => {
        node.position({ x: x + widths[index] / 2, y: area.y2 + 70 });
        x += widths[index] + gap;
      });
    }
    // Fit, but never below a readable zoom: a larger neighborhood opens at its top-left corner and pans instead.
    const view = () => {
      cy.fit(undefined, 40);
      const clip = cy.zoom() < READABLE_ZOOM;
      if (clip) {
        const area = cy.elements().boundingBox();
        cy.viewport({ zoom: READABLE_ZOOM, pan: { x: 40 - area.x1 * READABLE_ZOOM, y: 40 - area.y1 * READABLE_ZOOM } });
      }
      setClipped(clip);
    };
    view();
    instance.current = cy;
    cy.on('tap', 'node:childless', event => onSelect(event.target.data('source')));
    const resize = new ResizeObserver(() => {
      cy.resize();
      view();
    });
    resize.observe(container.current);
    return () => {
      resize.disconnect();
      cy.destroy();
      instance.current = null;
    };
  }, [graph, policyEvidence, onSelect, outsideGuard, flagStatus, tenantId, outsideOnly]);
  useEffect(() => {
    instance.current
      ?.style()
      .selector('node:childless, edge')
      .style('label', labels ? 'data(label)' : '')
      .update();
  }, [labels, graph, outsideOnly]);
  useEffect(() => {
    const cy = instance.current;
    if (!cy) return;
    cy.elements().unselect();
    if (selected?.id) cy.getElementById(selected.id).select();
  }, [selected, graph, outsideOnly]);
  return (
    <div className="graph-shell">
      <div className="graph-tools">
        <span>FOCUSED NEIGHBORHOOD</span>
        <div>
          <button className="small-button" onClick={() => setOutsideOnly(!outsideOnly)} aria-pressed={outsideOnly}>
            Outside guard only {outsideOnly ? 'on' : 'off'}
          </button>
          <button className="small-button" onClick={() => setLabels(!labels)} aria-pressed={labels}>
            Labels {labels ? 'on' : 'off'}
          </button>
          <button
            className="icon-button"
            title="Fit graph"
            aria-label="Fit graph"
            onClick={() => {
              instance.current?.fit(undefined, 40);
              setClipped(false);
            }}
          >
            <Icon name="fit" size={16} />
          </button>
        </div>
      </div>
      <div
        className="graph"
        ref={container}
        role="img"
        aria-label="Agent evidence network with shortened display labels. Use the evidence list below for full identifiers and accessible node selection."
      />
      {error && (
        <div className="graph-error">
          <Notice error>{error}</Notice>
        </div>
      )}
      {clipped && (
        <p className="graph-hint" role="status">
          Part of this neighborhood is outside the view. Drag to pan, or select Fit graph for an overview with smaller
          text.
        </p>
      )}
      {empty && (
        <div className="graph-error">
          <Notice>
            No outside-guard edge in this neighborhood. Undeclared paths and unevaluated identities remain unknown.
          </Notice>
        </div>
      )}
      <div className="graph-legend">
        <span>
          <i className="legend-agent" />
          Agent
        </span>
        <span>
          <i className="legend-task" />
          Task
        </span>
        <span>
          <i className="legend-mcp" />
          MCP
        </span>
        <span>
          <i className="legend-resource" />
          Resource
        </span>
        <span>
          <i className="legend-unknown" />
          Unknown / unavailable
        </span>
        <span>
          <i className="legend-conditional" />
          Conditional
        </span>
        <span>
          <i className="legend-policy" />
          Policy candidate · access unknown
        </span>
        <span>
          <i className="legend-outside" />
          Outside guard · declared direct path
        </span>
        <span>
          <i className="legend-reach" />
          Tool identity reaches this · candidate
        </span>
        <span>
          <i className="legend-guarded" />
          Guarded relationship
        </span>
        <span>
          <i className="legend-box" />
          Tenant / team box
        </span>
        <span>
          <i className="legend-crossing" />
          Crosses a box border
        </span>
        <span>
          <i className="legend-flag exposed" />
          {FLAG_NAME}: Exposed / Mitigated / Unknown (named on the agent)
        </span>
      </div>
    </div>
  );
}

/** A property of a graph node in words; identifiers keep their full value one click away. */
function PropertyValue({ name, value }) {
  const shown = fieldValue(name, value);
  return typeof shown === 'string' || Array.isArray(shown) ? <Identifier value={shown} /> : displayValue(shown);
}
/** The selected node's captured properties, and an accessible way to select a node without the canvas. */
export function Evidence({ node, graph, select }) {
  const nodes = graph?.nodes ?? [];
  const state = evidenceState(node);
  return (
    <section className="evidence-panel">
      <div className="section-heading">
        <h3>Evidence detail</h3>
        <Icon name="layers" size={17} />
      </div>
      <label className="field-label" htmlFor="evidence-node">
        Select a node
      </label>
      <select
        id="evidence-node"
        value={node?.id ?? ''}
        onChange={event => select(nodes.find(item => item.id === event.target.value) ?? null)}
      >
        <option value="">Choose from the graph</option>
        {nodes.map(item => (
          <option key={item.id} value={item.id}>
            {kindName(item.label)} · {nodeName(item)}
          </option>
        ))}
      </select>
      {node ? (
        <>
          <span className="eyebrow node-type">{kindName(node.label)}</span>
          <h4 className="node-name">{nodeName(node)}</h4>
          <Status
            tone={
              state.kind === 'blocked'
                ? 'danger'
                : ['unavailable', 'conditional', 'unknown'].includes(state.kind)
                  ? 'amber'
                  : 'neutral'
            }
          >
            {state.label}
          </Status>
          <dl className="property-list">
            {Object.entries(node.properties ?? {})
              .filter(([key]) => !['id', 'projection_id', 'source_id', 'entity_id'].includes(key))
              .map(([key, value]) => (
                <div key={key}>
                  <dt>{fieldLabel(key)}</dt>
                  <dd>
                    <PropertyValue name={key} value={value} />
                  </dd>
                </div>
              ))}
          </dl>
        </>
      ) : (
        <p className="subtle evidence-hint">
          Select a node to inspect its captured state, scope and supporting evidence.
        </p>
      )}
      <div className="evidence-footnote">
        <Icon name="shield" size={16} />
        <p>This map explains collected evidence. Agent Guard still checks each execution request.</p>
      </div>
    </section>
  );
}
