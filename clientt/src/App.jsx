import React, { Fragment } from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import './App.css';
import Navbar from './components/layout/Navbar';
import Landing from './components/layout/Landing';
import Register from './components/auth/Register';
import Login from './components/auth/Login';

const App = () => {
  return (
    <Router>
      <Fragment>
        <Landing />
        <Routes>
          <Route exact path="/" element={<Navbar /> } />
      
          <Route exact path="/register" element={<Register />} />
          <Route  path="/login" element={<Login /> } />
          
        </Routes>
      </Fragment>
    </Router>
  );
}

export default App;