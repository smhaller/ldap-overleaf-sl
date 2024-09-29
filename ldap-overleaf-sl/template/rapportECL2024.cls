\LoadClass[a4paper,12pt]{article}

\RequirePackage{silence}
\WarningFilter{fancyhdr}{\headheight is too small}
\WarningFilter{fancyhdr}{\footskip is too small}

%--------------------------------------

\RequirePackage[french]{babel}
\RequirePackage[utf8]{inputenc}
\RequirePackage[section]{placeins}
\RequirePackage[T1]{fontenc}
\RequirePackage{xcolor}
\RequirePackage{csquotes}
\RequirePackage{biblatex}
\RequirePackage{ragged2e}
\RequirePackage{lipsum}
\RequirePackage{booktabs}
\RequirePackage{amsmath} 
\RequirePackage{siunitx}
\RequirePackage{enumitem}
\RequirePackage{float}
\RequirePackage{graphicx}
\RequirePackage[justification=centering]{caption}
\RequirePackage{subcaption}
\RequirePackage{tikz}
\RequirePackage{fancyhdr}
\RequirePackage{url}
\RequirePackage[hidelinks]{hyperref}
\RequirePackage{geometry}
\geometry{left=2.5cm, right=2.5cm, top=2cm, bottom=5.5cm}
\RequirePackage{siunitx} 
\RequirePackage{tabularx}
\RequirePackage{microtype} 
\RequirePackage{pgfplots}
\pgfplotsset{compat=1.18}

%--------------------------------------

\definecolor{centrale_red}{RGB}{178,33,51} % Rouge centralien

%--------------------------------------

\sisetup{output-decimal-marker = {,}} % Séparateur décimal
\renewcommand{\headrulewidth}{0pt} % Retirer le trait de séparation de l'en-tête
\setlength{\footskip}{4cm}  % Augmente la distance entre le texte et le pied de page
\setlist[itemize]{label=\textbullet} % Défini la puce par défaut pour les itemize.
\setlist[itemize,2]{label=\textbf{--}}   %  Défini la puce par défaut pour les deuxièmes niveaux d'itemize.

%--------------------------------------

\newcommand{\enseignant}[1]{\renewcommand{\enseignant}{#1}}
\newcommand{\eleves}[1]{\renewcommand{\eleves}{#1}}
\newcommand{\titre}[1]{\renewcommand{\titre}{#1}}
\newcommand{\soustitre}[1]{\renewcommand{\soustitre}{#1}}

%--------------------------------------

% Header et Footer
\pagestyle{fancy}
\fancyheadoffset{1cm}
\setlength{\headheight}{2.5cm}
\fancyhf{}
\fancyhead[L]{\hspace*{0.645cm}\includegraphics[height=2.75cm]{logos/logo.png}}
\lfoot{\raisebox{-0.75cm}{\hspace{-8.5cm}\includegraphics[height=4cm]{logos/motif.png}}}

\newcommand{\fairepagedegarde}{
    \rfoot{} % Retirer le numéro de page de la page de garde
    \begin{centering}
    
        \vspace*{8cm}
        
        {\Huge \textbf{\textcolor{centrale_red}{\titre}} \par}
        
        \vspace{1cm}
        
        {\Large \textbf{\soustitre} \par}
    
        \vspace{2.5cm}
        
        \begin{minipage}{0.4\textwidth}
                \begin{flushleft} \large
                    \emph{\textbf{Élèves :}}\\ 
                    \eleves
                \end{flushleft}
            \end{minipage}
            ~
            \begin{minipage}{0.4\textwidth}
                \begin{flushright} \large
                    \emph{\textbf{Enseignants :}}\\
                    \enseignant
                \end{flushright}
            \end{minipage}
        
        \vfill
        
        {\large \today \par}
        
    \end{centering}
    \newpage
    
    \setcounter{page}{1}
    \rfoot{
      \raisebox{1cm}{
        \includegraphics[height=1.5cm]{logos/blason.png}
      }
      \raisebox{1.65cm}{ \makebox[0pt][c]{\hspace{-1.955cm}\textbf{\textcolor{white}{\thepage}}}}
      \hspace*{-0.67cm}
    }
}

%--------------------------------------

% Table des matières
\newcommand{\fairetabledesmatieres}{
    \tableofcontents
    \newpage
}

%--------------------------------------

% Insérer une figure
\newcommand{\insererfigure}[4]{
    \begin{figure}[H]
        \centering
        \includegraphics[width=#2]{#1}
        \caption{#3}
        \label{fig:#4}
    \end{figure}
}

%--------------------------------------

% Insérer une bibliographie
\newcommand{\insererbiblio}{
    \newpage
    \section{Bibliographie}
    \newrefcontext[sorting=none]
    \printbibliography[heading=none]
    \newpage
}