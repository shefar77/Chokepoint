/// <reference types="vite/client" />

declare module 'cytoscape-fcose' {
  import type cytoscape from 'cytoscape';

  const extension: cytoscape.Ext;
  export default extension;
}
