import Button from "react-bootstrap/Button";
import Table from "react-bootstrap/Table";
import { FilePicker } from "react-file-picker";
import Form from "react-bootstrap/Form";
import "./App.css";
import { useEffect, useState } from "react";

function DataGrid({ data }) {
  const [response, setResponse] = useState();
  const date = new Date();
  useEffect(() => {
    setResponse(data);
  }, [data]);
  return (
    <Table striped bordered hover>
      <thead>
        <tr>
          <th>hash_value (MD5 or Sha256)</th>
          <th>Fortinet detection name </th>
          <th>Number of engines detected</th>
          <th>Scan Date</th>
        </tr>
      </thead>
      <tbody>
        {response &&
          response["data"].map((item) => (
            <tr>
              <td>{item.hash_key}</td>
              <td>{item.detection_name}</td>
              <td>{item.number_of_engine}</td>
              <td>{item.scan_date}</td>
            </tr>
          ))}
      </tbody>
    </Table>
  );
}

function App() {
  const [filename, setFileName] = useState("");
  const [file, setFile] = useState([]);
  const [response, setResponse] = useState(null);
  const handleSave = function () {
    setResponse(null);
    const formData = new FormData();
    formData.append("file", file);

    fetch("http://localhost:8080/upload", {
      method: "POST",
      mode: "cors",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        console.log(data);
        setResponse(data);
      });
  };
  return (
    <div className="App">
      <div className="row">
        <FilePicker
          style={{ width: "unset" }}
          className="col-3"
          extensions={["txt"]}
          onChange={(FileObject) => {
            setFileName(FileObject.name);
            setFile(FileObject);
          }}
          onError={(errMsg) => {
            alert(errMsg);
          }}
        >
          <Button variant="secondary">Click to upload text file</Button>
        </FilePicker>
        <Form className="col-4">
          <Form.Control
            disabled
            value={filename}
            type="text"
            placeholder="File name"
          />
        </Form>
        <Button className="col-1" onClick={handleSave} variant="primary">
          Submit
        </Button>
        &nbsp;
        <Button className="col-2" onClick={handleSave} variant="secondary">
          Export Report
        </Button>
      </div>
      <br></br>
      {response ? <DataGrid data={response} /> : null}
    </div>
  );
}

export default App;
