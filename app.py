from flask import Flask, render_template_string  
from rdflib import Graph, Namespace, RDF, RDFS, URIRef, FOAF  
  
app = Flask(__name__)  
  
# === Load RDF ===  
g = Graph()  
g.parse("data/model.ttl", format="turtle")  
  
# === Namespaces ===  
EX = Namespace("http://example.com/ontology/")  
DCT = Namespace("http://purl.org/dc/terms/")  
FIBO_ORG = Namespace("https://spec.edmcouncil.org/fibo/ontology/FND/Organizations/Organizations/")  
FIBO_LEI = Namespace("https://spec.edmcouncil.org/fibo/ontology/BE/LegalEntities/LegalEntities/")  
  
# === Helper functions ===  
def get_severity(uri):  
    for sev in g.objects(uri, EX.cvssSeverity):  
        return str(sev)  
    return None  
  
def edge_style(predicate):  
    pred_str = str(predicate)  
    if pred_str.endswith("dependsOn"):  
        return "#1f77b4", False  
    elif pred_str.endswith("runsOn"):  
        return "#2ca02c", False  
    elif pred_str.endswith("hasVulnerability"):  
        return "#d62728", True  
    elif pred_str.endswith("hasMember"):  
        return "#9467bd", False  
    elif pred_str.endswith("supportsCapability"):  
        return "#ff00ff", True  
    return "#7f7f7f", False  
  
def node_color(node_uri):  
    types = list(g.objects(node_uri, RDF.type))  
    if EX.Application in types:  
        return "#f4b400"  
    elif EX.Library in types:  
        return "#4285f4"  
    elif EX.InfrastructureHardware in types:  
        return "#ea4335"  
    elif EX.Vulnerability in types:  
        sev = get_severity(node_uri)  
        return {  
            "Critical": "#8b0000",  
            "High": "#ff4500",  
            "Medium": "#ffa500",  
            "Low": "#9acd32"  
        }.get(sev, "#cc00cc")  
    elif FIBO_LEI.LegalEntity in types:  
        return "#0f9d58"  
    elif EX.BusinessCapability in types:  
        return "#ff00ff"  
    return "#9e9e9e"  
  
def get_label(uri):  
    for lbl in g.objects(uri, RDFS.label):  
        return str(lbl)  
    for lbl in g.objects(uri, FOAF.name):  
        return str(lbl)  
    for lbl in g.objects(uri, DCT.title):  
        return str(lbl)  
    for lbl in g.objects(uri, EX.cveId):  
        return str(lbl)  
    return uri.split("#")[-1].split("/")[-1]  
  
def get_node_group(node_uri):  
    types = list(g.objects(node_uri, RDF.type))  
    if FIBO_LEI.LegalEntity in types:  
        return 1  
    elif EX.Application in types:  
        return 2  
    elif EX.Library in types:  
        return 3  
    elif EX.InfrastructureHardware in types:  
        return 4  
    elif EX.Vulnerability in types:  
        return 5  
    elif EX.BusinessCapability in types:  
        return 7  
    return 6  
  
def is_visual_entity(uri):  
    types = set(g.objects(uri, RDF.type))  
    allowed_types = {  
        FIBO_LEI.LegalEntity,  
        EX.Application,  
        EX.Library,  
        EX.InfrastructureHardware,  
        EX.Vulnerability,  
        EX.BusinessCapability  
    }  
    return any(t in allowed_types for t in types)  
  
def get_node_properties(uri):  
    props = []  
    for p, o in g.predicate_objects(uri):  
        if isinstance(o, URIRef) and not is_visual_entity(o):  
            props.append({"key": get_label(p), "value": get_label(o)})  
        elif not isinstance(o, URIRef):  
            props.append({"key": get_label(p), "value": str(o)})  
    return props  
  
def build_graph_data():  
    nodes_data = []  
    edges_data = []  
    for s, p, o in g:  
        if not isinstance(s, URIRef) or not isinstance(o, URIRef):  
            continue  
        if not (is_visual_entity(s) and is_visual_entity(o)):  
            continue  
  
        if not any(n["id"] == str(s) for n in nodes_data):  
            nodes_data.append({  
                "id": str(s),  
                "label": get_label(s),  
                "color": node_color(s),  
                "group": get_node_group(s),  
                "props": get_node_properties(s)  
            })  
        if not any(n["id"] == str(o) for n in nodes_data):  
            nodes_data.append({  
                "id": str(o),  
                "label": get_label(o),  
                "color": node_color(o),  
                "group": get_node_group(o),  
                "props": get_node_properties(o)  
            })  
  
        color, dashes = edge_style(p)  
        edges_data.append({  
            "id": str(s) + "_" + str(o),  
            "from": str(s),  
            "to": str(o),  
            "label": get_label(p),  
            "title": get_label(p),  
            "color": color,  
            "dashes": dashes  
        })  
  
    return nodes_data, edges_data  
  
@app.route("/")  
def index():  
    nodes_data, edges_data = build_graph_data()  
  
    html_template = """  
    <!DOCTYPE html>  
    <html>  
    <head>  
        <meta charset="utf-8">  
        <title>Fancy RDF Graph</title>  
        <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>  
        <link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis-network.min.css" rel="stylesheet" />  
        <style>  
            body { font-family: 'Segoe UI', sans-serif; background: #f9f9f9; margin:0; }  
            h1 { background: #4285f4; color: white; padding: 10px; margin:0; }  
            #network { width: 75%; height: 90vh; float: left; border: 2px solid #ccc; background: white; border-radius: 6px; }  
            #sidepanel { width: 23%; float: right; border: 2px solid #ccc; padding: 10px; height: 90vh; overflow-y: auto; background: white; border-radius: 6px; }  
            .color-box { width: 14px; height: 14px; display: inline-block; margin-right: 5px; vertical-align: middle; border-radius: 3px; }  
            .legend { margin-bottom: 10px; font-size: 14px; padding: 5px; background: #f1f1f1; border-radius: 4px; }  
            .search-bar { margin-bottom: 10px; }  
            button { background: #4285f4; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }  
            button:hover { background: #3367d6; }  
            input[type=text] { padding: 5px; border: 1px solid #ccc; border-radius: 4px; }  
        </style>  
    </head>  
    <body>  
        <h1>Fancy Expand / Collapse RDF Graph</h1>  
  
        <div class="legend">  
            <b>Legend:</b><br>  
            <span><span class="color-box" style="background:#0f9d58"></span> Organization</span> |  
            <span><span class="color-box" style="background:#f4b400"></span> Application</span> |  
            <span><span class="color-box" style="background:#4285f4"></span> Library</span> |  
            <span><span class="color-box" style="background:#ea4335"></span> Infrastructure</span> |  
            <span><span class="color-box" style="background:#8b0000"></span> Critical CVE</span> |  
            <span><span class="color-box" style="background:#ff4500"></span> High CVE</span> |  
            <span><span class="color-box" style="background:#ffa500"></span> Medium CVE</span> |  
            <span><span class="color-box" style="background:#9acd32"></span> Low CVE</span> |  
            <span><span class="color-box" style="background:#ff00ff"></span> Business Capability</span>  
        </div>  
  
        <div class="search-bar">  
            <input type="text" id="searchInput" placeholder="Search node by name..." style="width:200px;">  
            <button type="button" onclick="searchNode()">Search</button>  
            <button type="button" onclick="resetView()">Reset View</button>  
        </div>  
  
        <div id="network"></div>  
        <div id="sidepanel"><b>Click a node to see properties</b></div>  
  
        <script>  
            var allNodes = {{ nodes_data | tojson }};  
            var allEdges = {{ edges_data | tojson }};  
            var startNodes = allNodes.filter(n => n.group === 1 || n.group === 7);  
            var startEdges = [];  
  
            var nodes = new vis.DataSet(startNodes.map(n => Object.assign({expanded: false}, n)));  
            var edges = new vis.DataSet(startEdges);  
  
            var container = document.getElementById('network');  
            var data = { nodes: nodes, edges: edges };  
            var options = {  
                nodes: { shape: 'dot', size: 20, font: { size: 14, color: '#333' }, borderWidth: 2, shadow: true },  
                edges: { arrows: 'to', smooth: { type: 'dynamic' }, color: { color: '#888', highlight: '#ff9900' }, shadow: true },  
                physics: { stabilization: true },  
                interaction: { navigationButtons: true, keyboard: true, hover: true },  
                groups: {  
                    1: { color: '#0f9d58' },  
                    2: { color: '#f4b400' },  
                    3: { color: '#4285f4' },  
                    4: { color: '#ea4335' },  
                    5: { color: '#ff4500' },  
                    6: { color: '#9e9e9e' },  
                    7: { color: '#ff00ff' }  
                }  
            };  
            var network = new vis.Network(container, data, options);  
  
            function toggleNode(nodeId) {  
                var node = nodes.get(nodeId);  
                if (!node) return;  
                if (!node.expanded) {  
                    var neighborEdges = allEdges.filter(e => e.from === nodeId || e.to === nodeId);  
                    neighborEdges.forEach(e => {  
                        if (!edges.get(e.id)) edges.add(e);  
                        var otherId = (e.from === nodeId) ? e.to : e.from;  
                        if (!nodes.get(otherId)) {  
                            var fullNode = allNodes.find(n => n.id === otherId);  
                            if (fullNode) nodes.add(Object.assign({expanded: false}, fullNode));  
                        }  
                    });  
                    node.expanded = true;  
                    nodes.update(node);  
                } else {  
                    var neighborEdges = edges.get().filter(e => e.from === nodeId || e.to === nodeId);  
                    neighborEdges.forEach(e => {  
                        var otherId = (e.from === nodeId) ? e.to : e.from;  
                        var stillConnected = edges.get().some(ed => {  
                            if (ed.id === e.id) return false;  
                            return (ed.from === otherId || ed.to === otherId);  
                        });  
                        if (!stillConnected) { nodes.remove({id: otherId}); }  
                        edges.remove({id: e.id});  
                    });  
                    node.expanded = false;  
                    nodes.update(node);  
                }  
            }  
  
            function searchNode() {  
                var query = document.getElementById("searchInput").value.toLowerCase();  
                var found = allNodes.find(n => n.label.toLowerCase().includes(query));  
                if (found) {  
                    if (!nodes.get(found.id)) { nodes.add(Object.assign({expanded: false}, found)); }  
                    network.focus(found.id, { scale: 1.5, animation: { duration: 800, easingFunction: "easeInOutQuad" } });  
                    network.selectNodes([found.id]);  
                } else { alert("Node not found"); }  
            }  
  
            function resetView() {  
                var initialIds = startNodes.map(n => n.id);  
                nodes.clear();  
                edges.clear();  
                nodes.add(startNodes.map(n => Object.assign({expanded: false}, n)));  
                network.fit({ animation: { duration: 500 } });  
            }  
  
            network.on("click", function(params) {  
                if (params.nodes.length > 0) {  
                    var nodeId = params.nodes[0];  
                    toggleNode(nodeId);  
                    var nodeData = nodes.get(nodeId);  
                    var html = "<h3>" + nodeData.label + "</h3><ul>";  
                    nodeData.props.forEach(function(p) {  
                        html += "<li><b>" + p.key + ":</b> " + p.value + "</li>";  
                    });  
                    html += "</ul>";  
                    document.getElementById("sidepanel").innerHTML = html;  
                }  
            });  
        </script>  
    </body>  
    </html>  
    """  
    return render_template_string(html_template, nodes_data=nodes_data, edges_data=edges_data)  
  
if __name__ == "__main__":  
    app.run(debug=True)  