import Button from "react-bootstrap/Button";
import Table from "react-bootstrap/Table";
import { FilePicker } from "react-file-picker";
import Form from "react-bootstrap/Form";
import "./App.css";
import Spinner from "react-bootstrap/Spinner";
import { useEffect, useState } from "react";

const MySpinner = function () {
  return (
    <div>
      <Spinner animation="grow" size="sm" />
      <Spinner animation="grow" size="sm" />
      <Spinner animation="grow" size="sm" />
    </div>
  );
};

function DataGrid({ data }) {
  const [response, setResponse] = useState();
  useEffect(() => {
    console.log(data);
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
  const [showSpinner, setShowSpinner] = useState(false);
  const handleSave = function () {
    setResponse(null);
    const formData = new FormData();
    formData.append("file", file);
    setShowSpinner(true);
    fetch("http://localhost:8080/upload", {
      method: "POST",
      mode: "cors",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        console.log(data);
        setResponse(data);
        setShowSpinner(false);
      })
      .catch((error) => {
        setShowSpinner(false);
        alert("Error occurred");
        console.log(error);
      });
  };
  const fetchLatest = function () {
    setResponse(null);
    setShowSpinner(true);
    fetch("http://localhost:8080/getdata", {
      method: "GET",
      mode: "cors",
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("hello");
        console.log(data);
        setResponse(data);
        setShowSpinner(false);
      })
      .catch((error) => {
        setShowSpinner(false);
        console.log(error);
        alert("Error Occurred");
      });
  };
  return (
    <div className="App">
      <div className="row">
        <FilePicker
          style={{ width: "unset" }}
          className="col-2"
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
        <Form className="col-6">
          <Form.Control
            disabled
            value={filename}
            type="text"
            placeholder="File name"
          />
        </Form>
        <Button className="col-2" onClick={handleSave} variant="primary">
          Submit
        </Button>
        <Button
          style={{ marginLeft: "10px" }}
          className="col-2"
          onClick={fetchLatest}
          variant="primary"
        >
          Refresh
        </Button>
      </div>
      <br></br>
      {showSpinner ? <MySpinner /> : null}
      {response ? <DataGrid data={response} /> : null}
    </div>
  );
}

export default App;
