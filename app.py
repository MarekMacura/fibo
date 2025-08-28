from flask import Flask, render_template_string, request  
from rdflib import Graph, Namespace, RDF, RDFS  
  
app = Flask(__name__)  
  
# Load RDF  
g = Graph()  
g.parse("data/model.ttl", format="turtle")  
  
# Namespaces  
EX = Namespace("http://example.com/ontology/")  
DCT = Namespace("http://purl.org/dc/terms/")  
FOAF = Namespace("http://xmlns.com/foaf/0.1/")  
FIBO_ORG = Namespace("https://spec.edmcouncil.org/fibo/ontology/FND/Organizations/Organizations/")  
FIBO_LEI = Namespace("https://spec.edmcouncil.org/fibo/ontology/BE/LegalEntities/LegalEntities/")  
  
def build_graph_data(severity_filter=None):  
    nodes_data = []  
    edges_data = []  
  
    for s, p, o in g:  
        if severity_filter and (is_vulnerability(o) or is_vulnerability(s)):  
            sev_s = get_severity(s)  
            sev_o = get_severity(o)  
            if severity_filter not in (sev_s, sev_o):  
                continue  
  
        if not any(n["id"] == str(s) for n in nodes_data):  
            nodes_data.append({  
                "id": str(s),  
                "label": get_label(s),  
                "color": node_color(s),  
                "props": get_node_properties(s)  
            })  
  
        if not any(n["id"] == str(o) for n in nodes_data):  
            nodes_data.append({  
                "id": str(o),  
                "label": get_label(o),  
                "color": node_color(o),  
                "props": get_node_properties(o)  
            })  
  
        color, dashes = edge_style(p)  
        edges_data.append({  
            "id": str(s) + "_" + str(o),  
            "from": str(s),  
            "to": str(o),  
            "label": get_label(p),  
            "color": color,  
            "dashes": dashes  
        })  
  
    return nodes_data, edges_data  
  
def is_vulnerability(uri):  
    return EX.Vulnerability in g.objects(uri, RDF.type)  
  
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
    return "#7f7f7f", False  
  
def node_color(node_uri):  
    types = list(g.objects(node_uri, RDF.type))  
    if EX.Application in types:  
        return "#f4b400"  # yellow  
    elif EX.Library in types:  
        return "#4285f4"  # blue  
    elif EX.InfrastructureHardware in types:  
        return "#ea4335"  # red  
    elif EX.Vulnerability in types:  
        sev = get_severity(node_uri)  
        return {  
            "Critical": "#8b0000",  
            "High": "#ff4500",  
            "Medium": "#ffa500",  
            "Low": "#9acd32"  
        }.get(sev, "#cc00cc")  
    elif FIBO_LEI.LegalEntity in types:  
        return "#0f9d58"  # green  
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
  
def get_node_properties(uri):  
    props = []  
    for p, o in g.predicate_objects(uri):  
        props.append({"key": get_label(p), "value": str(o)})  
    return props  
  
def run_analysis(severity_filter=None):  
    results = []  
    for org_uri in g.subjects(RDF.type, FIBO_LEI.LegalEntity):  
        org_name = get_label(org_uri)  
        org_data = {"organization": org_name, "applications": []}  
  
        for app_uri in g.objects(org_uri, FIBO_ORG.hasMember):  
            app_name = get_label(app_uri)  
            vulns = set()  
  
            for lib in g.objects(app_uri, EX.dependsOn):  
                for vuln in g.objects(lib, EX.hasVulnerability):  
                    if not severity_filter or get_severity(vuln) == severity_filter:  
                        vulns.add(get_label(vuln))  
  
            for infra in g.objects(app_uri, EX.runsOn):  
                for vuln in g.objects(infra, EX.hasVulnerability):  
                    if not severity_filter or get_severity(vuln) == severity_filter:  
                        vulns.add(get_label(vuln))  
  
            org_data["applications"].append({  
                "application": app_name,  
                "vulnerabilities": sorted(list(vulns))  
            })  
  
        results.append(org_data)  
    return results  
  
@app.route("/", methods=["GET"])  
def index():  
    severity = request.args.get("severity")  
    nodes_data, edges_data = build_graph_data(severity_filter=severity)  
    analysis_data = run_analysis(severity_filter=severity)  
  
    html_template = """  
    <!DOCTYPE html>  
    <html>  
    <head>  
        <meta charset="utf-8">  
        <title>RDF Graph Visualization</title>  
        <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>  
        <link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis-network.min.css" rel="stylesheet" />  
        <style>  
            body { font-family: Arial, sans-serif; }  
            #network { width: 75%; height: 750px; float: left; border: 1px solid lightgray; }  
            #sidepanel { width: 23%; float: right; border: 1px solid lightgray; padding: 10px; height: 750px; overflow-y: auto; }  
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }  
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }  
            th { background-color: #f2f2f2; }  
            .legend { margin: 15px 0; padding: 10px; border: 1px solid #ccc; background: #fafafa; font-size: 14px; }  
            .color-box { width: 12px; height: 12px; display: inline-block; margin-right: 5px; vertical-align: middle; }  
            .search-bar { margin-bottom: 10px; }  
        </style>  
    </head>  
    <body>  
        <h1>RDF Graph Visualization</h1>  
        <form method="get">  
            <label>Filter by CVSS Severity:</label>  
            <select name="severity" onchange="this.form.submit()">  
                <option value="">-- All --</option>  
                {% for sev in ['Critical','High','Medium','Low'] %}  
                    <option value="{{sev}}" {% if request.args.get('severity') == sev %}selected{% endif %}>{{sev}}</option>  
                {% endfor %}  
            </select>  
        </form>  
  
        <div class="search-bar">  
            <input type="text" id="searchInput" placeholder="Search node by name..." style="width:200px;">  
            <button onclick="searchNode()">Search</button>  
        </div>  
  
        <div class="legend">  
            <b>Legend:</b><br>  
            <span><span class="color-box" style="background:#0f9d58"></span> Organization</span>  
            <span><span class="color-box" style="background:#f4b400"></span> Application</span>  
            <span><span class="color-box" style="background:#4285f4"></span> Library</span>  
            <span><span class="color-box" style="background:#ea4335"></span> Infrastructure</span>  
            <span><span class="color-box" style="background:#8b0000"></span> Critical CVE</span>  
            <span><span class="color-box" style="background:#ff4500"></span> High CVE</span>  
            <span><span class="color-box" style="background:#ffa500"></span> Medium CVE</span>  
            <span><span class="color-box" style="background:#9acd32"></span> Low CVE</span>  
        </div>  
  
        <div id="network"></div>  
        <div id="sidepanel"><b>Click a node to see properties</b></div>  
  
        <h2>Analysis: Organization → Applications → CVE {% if severity %}(filtered: {{severity}}){% endif %}</h2>  
        <table>  
            <tr>  
                <th>Organization</th>  
                <th>Application</th>  
                <th>Vulnerabilities (CVE)</th>  
            </tr>  
            {% for org in analysis_data %}  
                {% for app in org.applications %}  
                <tr>  
                    <td>{{org.organization}}</td>  
                    <td>{{app.application}}</td>  
                    <td>{{", ".join(app.vulnerabilities) if app.vulnerabilities else "None"}}</td>  
                </tr>  
                {% endfor %}  
            {% endfor %}  
        </table>  
  
        <script>  
            var nodesArray = {{ nodes_data | tojson }};  
            var edgesArray = {{ edges_data | tojson }};  
            var nodes = new vis.DataSet(nodesArray);  
            var edges = new vis.DataSet(edgesArray);  
  
            var container = document.getElementById('network');  
            var data = { nodes: nodes, edges: edges };  
            var options = {  
                nodes: { shape: 'dot', size: 18, font: { size: 14, color: '#333' }, shadow: false },  
                edges: { smooth: { type: 'dynamic' }, arrows: 'to', color: { opacity: 0.6 } },  
                physics: { stabilization: true },  
                interaction: { hover: true, navigationButtons: true, multiselect: true }  
            };  
            var network = new vis.Network(container, data, options);  
  
            var expandedNodes = {};  
            var highlightedNodes = {};  
  
            function searchNode() {  
                var query = document.getElementById("searchInput").value.toLowerCase();  
                var found = nodesArray.find(n => n.label.toLowerCase().includes(query));  
                if (found) {  
                    network.focus(found.id, { scale: 1.5, animation: true });  
                    nodes.update({id: found.id, shadow: {enabled: true, color: 'cyan', size: 15, x:0, y:0}, borderWidth: 3});  
                    highlightedNodes[found.id] = true;  
                } else {  
                    alert("Node not found");  
                }  
            }  
  
            function expandNodeImmediate(nodeId) {  
                edgesArray.forEach(function(e) {  
                    if ((e.from === nodeId || e.to === nodeId) && !edges.get(e.id)) {  
                        edges.add(e);  
                    }  
                });  
            }  
  
            function collapseNodeImmediate(nodeId) {  
                edges.get().forEach(function(e) {  
                    if (e.from === nodeId || e.to === nodeId) {  
                        edges.remove(e.id);  
                    }  
                });  
            }  
  
            function expandNodeRecursive(nodeId, visited = new Set()) {  
                if (visited.has(nodeId)) return;  
                visited.add(nodeId);  
                expandNodeImmediate(nodeId);  
                edgesArray.forEach(function(e) {  
                    if (e.from === nodeId || e.to === nodeId) {  
                        var neighbor = (e.from === nodeId) ? e.to : e.from;  
                        expandNodeRecursive(neighbor, visited);  
                        expandedNodes[neighbor] = true;  
                    }  
                });  
                expandedNodes[nodeId] = true;  
            }  
  
            function collapseNodeRecursive(nodeId, visited = new Set()) {  
                if (visited.has(nodeId)) return;  
                visited.add(nodeId);  
                edges.get().forEach(function(e) {  
                    if (e.from === nodeId || e.to === nodeId) {  
                        edges.remove(e.id);  
                        var neighbor = (e.from === nodeId) ? e.to : e.from;  
                        collapseNodeRecursive(neighbor, visited);  
                        expandedNodes[neighbor] = false;  
                    }  
                });  
                expandedNodes[nodeId] = false;  
            }  
  
            network.on("click", function(params) {  
                if (params.nodes.length > 0) {  
                    var nodeId = params.nodes[0];  
                    var nodeData = nodes.get(nodeId);  
  
                    var html = "<h3>" + nodeData.label + "</h3><ul>";  
                    nodeData.props.forEach(function(p) {  
                        html += "<li><b>" + p.key + ":</b> " + p.value + "</li>";  
                    });  
                    html += "</ul>";  
                    document.getElementById("sidepanel").innerHTML = html;  
  
                    if (highlightedNodes[nodeId]) {  
                        nodes.update({id: nodeId, shadow: false, borderWidth: 1});  
                        highlightedNodes[nodeId] = false;  
                    } else {  
                        nodes.update({id: nodeId, shadow: {enabled: true, color: 'yellow', size: 15, x:0, y:0}, borderWidth: 3});  
                        highlightedNodes[nodeId] = true;  
                    }  
  
                    if (expandedNodes[nodeId]) {  
                        collapseNodeImmediate(nodeId);  
                        expandedNodes[nodeId] = false;  
                    } else {  
                        expandNodeImmediate(nodeId);  
                        expandedNodes[nodeId] = true;  
                    }  
                }  
            });  
  
            network.on("doubleClick", function(params) {  
                if (params.nodes.length > 0) {  
                    var nodeId = params.nodes[0];  
                    if (expandedNodes[nodeId]) {  
                        collapseNodeRecursive(nodeId);  
                    } else {  
                        expandNodeRecursive(nodeId);  
                    }  
                }  
            });  
        </script>  
    </body>  
    </html>  
    """  
    return render_template_string(html_template,  
                                  nodes_data=nodes_data,  
                                  edges_data=edges_data,  
                                  analysis_data=analysis_data)  
  
if __name__ == "__main__":  
    app.run(debug=True)  