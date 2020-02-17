//
// Config.cs
//
// Author:
//       Stefan Thöni <stefan@savvy.ch>
//
// Copyright (c) 2020 Stefan Thöni
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Linq;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace MatrixLibCli
{
    public class MatrixClientClient : Config
    {
        public string ApiUrl { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public override IEnumerable<ConfigItem> ConfigItems
        {
            get
            {
                yield return new ConfigItemString("ApiUrl", v => ApiUrl = v);
                yield return new ConfigItemString("UserName", v => UserName = v);
                yield return new ConfigItemString("Password", v => Password = v);
            }
        }

        public override IEnumerable<SubConfig> SubConfigs => new SubConfig[0];

        public override IEnumerable<ConfigSection> ConfigSections => new ConfigSection[0];
    }

    public abstract class Config : ConfigSection
    {
        public abstract IEnumerable<ConfigSection> ConfigSections { get; }

        public override void Load(string filename)
        {
            foreach (var configSection in ConfigSections)
            {
                configSection.Load(filename);
            }

            base.Load(filename);
        }
    }

    public abstract class SubConfig
    {
        public string Tag { get; private set; }

        public SubConfig(string tag)
        {
            Tag = tag;
        }

        public abstract void Load(XElement element);
    }

    public class SubConfig<T> : SubConfig
    {
        private Func<XElement, T> _create;
        private Action<T> _assign;

        public SubConfig(string tag, Func<XElement, T> create, Action<T> assign)
            : base(tag)
        {
            _create = create;
            _assign = assign;
        }

        public override void Load(XElement element)
        {
            _assign(_create(element));
        }
    }

    public abstract class ConfigSection
    {
        public abstract IEnumerable<ConfigItem> ConfigItems { get; }

        public abstract IEnumerable<SubConfig> SubConfigs { get; }

        public virtual void Load(string filename)
        {
            var document = XDocument.Load(filename);
            Load(document.Root);
        }

        public virtual void Load(XElement root)
        {
            foreach (var configItem in ConfigItems)
            {
                configItem.Load(root);
            }

            foreach (var subConfig in SubConfigs)
            {
                foreach (var element in root.Elements(subConfig.Tag))
                {
                    subConfig.Load(element); 
                } 
            }
        }
    }

    public abstract class ConfigItem
    {
        public abstract void Load(XElement root);
    }

    public abstract class ConfigItem<T> : ConfigItem
    {
        protected string Tag { get; private set; }
        private Action<T> _assign;
        private bool _required;

        public ConfigItem(string tag, Action<T> assign, bool required)
        {
            Tag = tag;
            _assign = assign;
            _required = required;
        }

        protected abstract T Convert(string value);

        public override void Load(XElement root)
        {
            var elements = root.Elements(Tag);

            if (!elements.Any() && _required)
            {
                throw new XmlException("Config node " + Tag + " not found");
            }
            else if (elements.Count() >= 2)
            {
                throw new XmlException("Config node " + Tag + " ambigous");
            }

            if (elements.Any())
            {
                _assign(Convert(elements.Single().Value));
            }
        }
    }

    public abstract class ConfigMultiItem<T> : ConfigItem
    {
        protected string Tag { get; private set; }
        private Action<T> _add;

        public ConfigMultiItem(string tag, Action<T> add)
        {
            Tag = tag;
            _add = add;
        }

        protected abstract T Convert(string value);

        public override void Load(XElement root)
        {
            var elements = root.Elements(Tag);

            foreach (var element in elements)
            {
                _add(Convert(element.Value));
            }
        }
    }

    public class ConfigItemString : ConfigItem<string>
    {
        public ConfigItemString(string tag, Action<string> assign, bool required = true)
            : base(tag, assign, required)
        {
        }

        protected override string Convert(string value)
        {
            return value;
        }
    }

    public class ConfigMultiItemString : ConfigMultiItem<string>
    {
        public ConfigMultiItemString(string tag, Action<string> add)
            : base(tag, add)
        {
        }

        protected override string Convert(string value)
        {
            return value;
        }
    }

    public class ConfigItemInt32 : ConfigItem<int>
    {
        public ConfigItemInt32(string tag, Action<int> assign, bool required = true)
            : base(tag, assign, required)
        {
        }

        protected override int Convert(string value)
        {
            if (int.TryParse(value, out int result))
            {
                return result;
            }
            else
            {
                throw new XmlException("Cannot convert value of config node " + Tag + " to integer"); 
            }
        }
    }

    public class ConfigItemBytes : ConfigItem<byte[]>
    {
        public ConfigItemBytes(string tag, Action<byte[]> assign, bool required = true) 
            : base(tag, assign, required)
        {
        }

        protected override byte[] Convert(string value)
        {
            var bytes = value.TryParseHexBytes();

            if (bytes != null)
            {
                return bytes;
            }
            else
            {
                throw new XmlException("Cannot convert value of config node " + Tag + " to bytes"); 
            }
        }
    }
}
