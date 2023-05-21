import React from 'react';
import MainRouter from './MainRouter';
import { hot } from 'react-hot-loader'; 
import { BrowserRouter } from 'react-router-dom';
import { ThemeProvider } from '@material-ui/core';
import theme from './theme';

const App = () => {
    return(
        <BrowserRouter>
            <ThemeProvider theme={theme}>
                <MainRouter/>
            </ThemeProvider>
        </BrowserRouter>
    );
}

export default hot(module) (App);